package security

import (
	"context"
	"fmt"
	"log/slog"
	"sift/audit"
	"sift/audit/progress"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/shield"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
)

var sensitivePortSet = map[int32]string{
	27017: "mongodb",
	27018: "mongodb",
	3306:  "mysql",
	5432:  "postgresql",
	6379:  "redis",
	9200:  "elasticsearch",
	9300:  "elasticsearch",
	11211: "memcached",
	1433:  "mssql",
	1521:  "oracle",
	5439:  "redshift",
	8529:  "arangodb",
	7474:  "neo4j",
	28015: "rethinkdb",
}

type elbEntry struct {
	name          string
	arn           string
	dnsName       string
	scheme        string  // "internet-facing" or "internal"
	lbType        string  // "application" or "network"
	listenerPorts []int32 // ports
	openToWorld   bool
	dbPortExposed bool
	tags          map[string]string
}

func parseELB(
	ctx context.Context,
	elbClient *elbv2.Client,
	ec2Client *ec2.Client,
	lb elbtypes.LoadBalancer,
) elbEntry {
	e := elbEntry{
		name:    aws.ToString(lb.LoadBalancerName),
		arn:     aws.ToString(lb.LoadBalancerArn),
		dnsName: aws.ToString(lb.DNSName),
		scheme:  string(lb.Scheme),
		lbType:  string(lb.Type),
	}

	// Get tags
	tagResp, err := elbClient.DescribeTags(ctx, &elbv2.DescribeTagsInput{
		ResourceArns: []string{e.arn},
	})
	if err == nil {
		for _, desc := range tagResp.TagDescriptions {
			e.tags = make(map[string]string, len(desc.Tags))
			for _, t := range desc.Tags {
				e.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
		}
	}

	// Get listeners
	listResp, err := elbClient.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
		LoadBalancerArn: &e.arn,
	})
	if err == nil {
		for _, l := range listResp.Listeners {
			port := aws.ToInt32(l.Port)
			e.listenerPorts = append(e.listenerPorts, port)
			if _, ok := sensitivePortSet[port]; ok {
				e.dbPortExposed = true
			}
		}
	}

	// Check security groups for open-to-world
	var sgIDs []string
	for _, sg := range lb.SecurityGroups {
		sgIDs = append(sgIDs, sg)
	}
	if len(sgIDs) > 0 {
		openSGs := FindOpenSGs(ctx, ec2Client, sgIDs)
		for _, id := range sgIDs {
			if openSGs[id] {
				e.openToWorld = true
				break
			}
		}
	} else if e.scheme == "internet-facing" {
		// NLBs without SGs are open by default if internet-facing
		e.openToWorld = true
	}

	return e
}

func elbRisk(scheme string, dbPortExposed, openToWorld bool) string {
	if scheme != "internet-facing" {
		return "MINIMAL"
	}
	switch {
	case dbPortExposed && openToWorld:
		return "CRITICAL"
	case openToWorld:
		return "HIGH"
	case dbPortExposed:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func AuditELB(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	elbClient := elbv2.NewFromConfig(cfg)
	ec2Client := ec2.NewFromConfig(cfg)

	var allLBs []elbtypes.LoadBalancer
	paginator := elbv2.NewDescribeLoadBalancersPaginator(
		elbClient,
		&elbv2.DescribeLoadBalancersInput{},
	)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe load balancers: %w", err)
		}
		allLBs = append(allLBs, page.LoadBalancers...)
	}

	results := make([]audit.Finding, len(allLBs))
	bar := progress.NewBar(ctx, int64(len(allLBs)), "Auditing load balancers")

	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)
	var mu sync.Mutex
	var extraFindings []audit.Finding

	for i, lb := range allLBs {
		wg.Add(1)
		go func(i int, lb elbtypes.LoadBalancer) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			e := parseELB(ctx, elbClient, ec2Client, lb)
			risk := elbRisk(e.scheme, e.dbPortExposed, e.openToWorld)

			detail := fmt.Sprintf(
				"type=%s, scheme=%s, dns=%s, open_to_world=%t",
				e.lbType,
				e.scheme,
				e.dnsName,
				e.openToWorld,
			)
			if e.dbPortExposed {
				detail += ", sensitive_port_exposed=true"
			}

			results[i] = audit.Finding{
				Service:    "elb",
				ResourceID: e.name,
				Tags:       e.tags,
				Check:      "lb_exposure",
				Status:     statusFromRisk(risk),
				Detail:     detail,
				RiskLevel:  risk,
			}

			// DDoS readiness for internet-facing ALBs
			if e.scheme == "internet-facing" && e.lbType == "application" {
				ddosFindings := checkDDoSReadiness(ctx, cfg, e.arn, e.name, e.tags)
				mu.Lock()
				extraFindings = append(extraFindings, ddosFindings...)
				mu.Unlock()
			}
			bar.Add(1)
		}(i, lb)
	}
	wg.Wait()

	return append(results, extraFindings...), nil
}

func checkDDoSReadiness(
	ctx context.Context,
	cfg aws.Config,
	arn, name string,
	tags map[string]string,
) []audit.Finding {
	var findings []audit.Finding

	wafClient := wafv2.NewFromConfig(cfg)
	shieldClient := shield.NewFromConfig(cfg, func(o *shield.Options) {
		o.Region = "us-east-1" // Shield API is global
	})

	// Check WAF association
	hasWAF := false
	hasRateRule := false
	wafResp, err := wafClient.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{
		ResourceArn: &arn,
	})
	if err != nil {
		slog.Debug("waf check failed", "elb", name, "error", err)
	} else if wafResp.WebACL != nil {
		hasWAF = true
		// Check for rate-based rules
		for _, rule := range wafResp.WebACL.Rules {
			if rule.Statement != nil && rule.Statement.RateBasedStatement != nil {
				hasRateRule = true
				break
			}
		}
	}

	if !hasWAF {
		findings = append(findings, audit.Finding{
			Service:    "elb",
			ResourceID: name,
			Tags:       tags,
			Check:      "ddos_no_waf",
			Status:     "FAIL",
			Detail:     "internet-facing ALB has no WAF associated",
			RiskLevel:  "HIGH",
			Remediation: &audit.Remediation{
				Action:     "Associate a WAF WebACL with rate-based rules",
				Command:    "aws wafv2 associate-web-acl --web-acl-arn <acl-arn> --resource-arn <lb-arn>",
				Evidence:   "No WAF WebACL associated with internet-facing ALB",
				Confidence: "HIGH",
				ActionRisk: "LOW",
			},
		})
	} else if !hasRateRule {
		findings = append(findings, audit.Finding{
			Service:    "elb",
			ResourceID: name,
			Tags:       tags,
			Check:      "ddos_no_rate_rule",
			Status:     "FAIL",
			Detail:     "WAF attached but no rate-based rule configured",
			RiskLevel:  "MEDIUM",
			Remediation: &audit.Remediation{
				Action:     "Add a rate-based rule to the WAF WebACL",
				Command:    "aws wafv2 update-web-acl --name <acl-name> --scope REGIONAL --rules <rate-rule>",
				Evidence:   "WAF WebACL has no rate-based rule to throttle flood traffic",
				Confidence: "HIGH",
				ActionRisk: "LOW",
			},
		})
	}

	// Check Shield Advanced protection
	_, err = shieldClient.DescribeProtection(ctx, &shield.DescribeProtectionInput{
		ResourceArn: &arn,
	})
	if err != nil {
		findings = append(findings, audit.Finding{
			Service:    "elb",
			ResourceID: name,
			Tags:       tags,
			Check:      "ddos_no_shield",
			Status:     "FAIL",
			Detail:     "internet-facing ALB not protected by Shield Advanced",
			RiskLevel:  "MEDIUM",
			Remediation: &audit.Remediation{
				Action:     "Enable AWS Shield Advanced",
				Command:    "aws shield create-protection --name <name> --resource-arn <lb-arn>",
				Evidence:   "Internet-facing ALB has no Shield Advanced protection",
				Confidence: "HIGH",
				ActionRisk: "LOW",
			},
		})
	}

	return findings
}
