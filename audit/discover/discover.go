package discover

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/list"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
)

var resourceTypeMap = map[string]string{
	"AWS::EC2::Instance":                        "ec2",
	"AWS::EC2::Volume":                          "ebs",
	"AWS::EC2::SecurityGroup":                   "ec2",
	"AWS::EC2::EIP":                             "ec2",
	"AWS::EC2::NatGateway":                      "network",
	"AWS::EC2::VPNConnection":                   "vpn",
	"AWS::S3::Bucket":                           "s3",
	"AWS::RDS::DBInstance":                      "rds",
	"AWS::Lambda::Function":                     "lambda",
	"AWS::DynamoDB::Table":                      "dynamodb",
	"AWS::EKS::Cluster":                         "eks",
	"AWS::ElasticLoadBalancingV2::LoadBalancer": "elb",
	"AWS::IAM::Role":                            "iam",
	"AWS::KMS::Key":                             "kms",
	"AWS::SNS::Topic":                           "sns",
	"AWS::SQS::Queue":                           "sqs",
	"AWS::SecretsManager::Secret":               "secrets",
	"AWS::ECR::Repository":                      "ecr",
	"AWS::Glue::Job":                            "glue",
	"AWS::Kinesis::Stream":                      "kinesis",
	"AWS::ElastiCache::CacheCluster":            "elasticache",
	"AWS::OpenSearch::Domain":                   "opensearch",
	"AWS::Redshift::Cluster":                    "redshift",
	"AWS::DMS::ReplicationInstance":             "dms",
	"AWS::SageMaker::NotebookInstance":          "sagemaker",
	"AWS::CloudFront::Distribution":             "cloudfront",
	"AWS::WAFv2::WebACL":                        "waf",
	"AWS::Backup::BackupVault":                  "backup",
	"AWS::StepFunctions::StateMachine":          "stepfunctions",
	"AWS::EFS::FileSystem":                      "efs",
	"AWS::MSK::Cluster":                         "msk",
	"AWS::DocDB::DBCluster":                     "docdb",
	"AWS::Events::EventBus":                     "eventbridge",
	"AWS::Route53::HostedZone":                  "route53",
	"AWS::ACM::Certificate":                     "acm",
	"AWS::CloudWatch::LogGroup":                 "cloudwatch",
}

type ServiceInfo struct {
	Name     string
	Count    int
	Security bool
	Cost     bool
	List     bool
}

func Discover(ctx context.Context, cfg aws.Config) ([]ServiceInfo, error) {
	client := configservice.NewFromConfig(cfg)

	resp, err := client.GetDiscoveredResourceCounts(
		ctx,
		&configservice.GetDiscoveredResourceCountsInput{},
	)
	if err != nil {
		return nil, fmt.Errorf("get discovered resource counts: %w", err)
	}

	securityServices := audit.ValidServices("security")
	costServices := audit.ValidServices("cost")
	listServices := make(map[string]bool)
	for _, s := range list.Services() {
		listServices[s] = true
	}

	counts := make(map[string]int)
	for _, rc := range resp.ResourceCounts {
		resType := string(rc.ResourceType)
		if svc, ok := resourceTypeMap[resType]; ok {
			counts[svc] += int(rc.Count)
		}
	}

	var services []ServiceInfo
	for svc, count := range counts {
		services = append(services, ServiceInfo{
			Name:     svc,
			Count:    count,
			Security: securityServices[svc],
			Cost:     costServices[svc],
			List:     listServices[svc],
		})
	}

	sort.Slice(services, func(i, j int) bool {
		return services[i].Count > services[j].Count
	})

	return services, nil
}

func FormatOutput(services []ServiceInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  %-16s %8s %s\n", "SERVICE", "COUNT", "COVERAGE"))
	sb.WriteString(fmt.Sprintf("  %-16s %8s %s\n", "-------", "-----", "--------"))

	var secSvcs, costSvcs []string
	var uncovered []string

	for _, s := range services {
		var coverage []string
		if s.Security {
			coverage = append(coverage, "security")
			secSvcs = append(secSvcs, s.Name)
		}
		if s.Cost {
			coverage = append(coverage, "cost")
			costSvcs = append(costSvcs, s.Name)
		}
		if s.List {
			coverage = append(coverage, "list")
		}

		marker := "✓"
		coverStr := strings.Join(coverage, ", ")
		if len(coverage) == 0 {
			marker = "X"
			coverStr = "not covered"
			uncovered = append(uncovered, s.Name)
		}

		sb.WriteString(fmt.Sprintf("  %-16s %8d %s %s\n", s.Name, s.Count, marker, coverStr))
	}

	sb.WriteString("\nSuggested commands:\n")
	if len(secSvcs) > 0 {
		sb.WriteString(fmt.Sprintf("  sift security --service %s\n", strings.Join(secSvcs, ",")))
	}
	if len(costSvcs) > 0 {
		sb.WriteString(fmt.Sprintf("  sift cost --service %s\n", strings.Join(costSvcs, ",")))
	}

	return sb.String()
}
