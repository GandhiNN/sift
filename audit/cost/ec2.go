package cost

import (
	"context"
	"fmt"
	"strings"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

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
				findings = append(findings, audit.Finding{
					Service:    "ec2",
					ResourceID: aws.ToString(inst.InstanceId),
					Check:      "stopped_instance",
					Status:     "WARN",
					Detail: fmt.Sprintf(
						"type=%s, EBS volumes still incurring cost",
						string(inst.InstanceType),
					),
					RiskLevel: "MEDIUM",
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
				iType := string(inst.InstanceType)
				for _, prefix := range PrevGenPrefixes {
					if strings.HasPrefix(iType, prefix) {
						findings = append(findings, audit.Finding{
							Service:    "ec2",
							ResourceID: aws.ToString(inst.InstanceId),
							Check:      "previous_gen_instance",
							Status:     "WARN",
							Detail:     fmt.Sprintf("type=%s, consider upgrading", iType),
							RiskLevel:  "LOW",
						})
						break
					}
				}
			}
		}
	}

	// Unused Elastic IPs
	addrs, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err == nil {
		for _, addr := range addrs.Addresses {
			if addr.AssociationId == nil {
				findings = append(findings, audit.Finding{
					Service:    "eip",
					ResourceID: aws.ToString(addr.AllocationId),
					Check:      "unused_elastic_ip",
					Status:     "WARN",
					Detail:     fmt.Sprintf("ip=%s", aws.ToString(addr.PublicIp)),
					RiskLevel:  "LOW",
				})
			}
		}
	}

	return findings, nil
}
