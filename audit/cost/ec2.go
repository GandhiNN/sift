package cost

import (
	"context"
	"fmt"
	"strings"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type ec2CostInstance struct {
	id           string
	instanceType string
	tags         map[string]string
}

func parseEC2CostInstance(inst ec2types.Instance) ec2CostInstance {
	tags := make(map[string]string, len(inst.Tags))
	for _, t := range inst.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return ec2CostInstance{
		id:           aws.ToString(inst.InstanceId),
		instanceType: string(inst.InstanceType),
		tags:         tags,
	}
}

func AuditEC2Cost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := ec2.NewFromConfig(cfg)
	var findings []audit.Finding

	// Stopped instances
	stoppedPaginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{{
			Name:   aws.String("instance-state-name"),
			Values: []string{"stopped"},
		}},
	})
	for stoppedPaginator.HasMorePages() {
		page, err := stoppedPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe stopped instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				i := parseEC2CostInstance(inst)
				findings = append(findings, audit.Finding{
					Service:    "ec2",
					ResourceID: i.id,
					Tags:       i.tags,
					Check:      "stopped_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, EBS volumes still incurring cost",
						i.instanceType,
					),
					RiskLevel:            "MEDIUM",
					EstimatedMonthlyCost: pricing.EC2Monthly(i.instanceType),
					Remediation: remediation.Recommend(
						"ec2",
						"stopped_instance",
						i.id,
						"instasnce in stopped state",
					),
				})
			}
		}
	}

	// Previous-gen instances
	runningPaginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{{
			Name:   aws.String("instance-state-name"),
			Values: []string{"running"},
		}},
	})
	for runningPaginator.HasMorePages() {
		page, err := runningPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe running instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				i := parseEC2CostInstance(inst)
				isPrevGen := false
				for _, prefix := range PrevGenPrefixes {
					if strings.HasPrefix(i.instanceType, prefix) {
						isPrevGen = true
						findings = append(findings, audit.Finding{
							Service:    "ec2",
							ResourceID: i.id,
							Tags:       i.tags,
							Check:      "previous_gen_instance",
							Status:     "WARN",
							Detail: fmt.Sprintf(
								"type=%s, consider upgrading",
								i.instanceType,
							),
							RiskLevel:            "LOW",
							EstimatedMonthlyCost: pricing.EC2Monthly(i.instanceType),
							Remediation: remediation.Recommend(
								"ec2",
								"previous_gen_instance",
								i.id,
								"previous-gen instance type",
							),
						})
						break
					}
				}
				if !isPrevGen {
					findings = append(findings, audit.Finding{
						Service:    "ec2",
						ResourceID: i.id,
						Tags:       i.tags,
						Check:      "previous_gen_instance",
						Status:     "PASS",
						Detail: fmt.Sprintf(
							"type=%s, current generation",
							i.instanceType,
						),
						RiskLevel:            "MINIMAL",
						EstimatedMonthlyCost: pricing.EC2Monthly(i.instanceType),
					})
				}
			}
		}
	}

	// Unused Elastic IPs
	addrs, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err == nil {
		for _, addr := range addrs.Addresses {
			if addr.AssociationId == nil {
				tags := make(map[string]string, len(addr.Tags))
				for _, t := range addr.Tags {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
				findings = append(findings, audit.Finding{
					Service:              "eip",
					ResourceID:           aws.ToString(addr.AllocationId),
					Tags:                 tags,
					Check:                "unused_elastic_ip",
					Status:               "WARN",
					Detail:               fmt.Sprintf("ip=%s", aws.ToString(addr.PublicIp)),
					RiskLevel:            "LOW",
					EstimatedMonthlyCost: pricing.ElasticIPMonthly(),
					Remediation: remediation.Recommend(
						"eip",
						"unused_elastic_ip",
						aws.ToString(addr.AllocationId),
						"EIP not associated",
					),
				})
			}
		}
	}

	return findings, nil
}
