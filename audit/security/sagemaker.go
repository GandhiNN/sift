package security

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
)

type sageMakerNotebook struct {
	name                 string
	status               string
	directInternetAccess bool
	subnetID             *string
	securityGroupIDs     []string
	roleARN              *string
}

func AuditSagemaker(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	notebooks, err := listNotebooks(ctx, cfg)
	if err != nil {
		return nil, err
	}

	ec2Client := ec2.NewFromConfig(cfg)

	// Batch-fetch all SGs and deduplicate
	sgSet := make(map[string]bool)
	for _, nb := range notebooks {
		for _, id := range nb.securityGroupIDs {
			sgSet[id] = true
		}
	}
	var sgIDs []string
	for id := range sgSet {
		sgIDs = append(sgIDs, id)
	}

	openSGs := FindOpenSGs(ctx, ec2Client, sgIDs)

	// Batch-fetch route tables for all unique subnets
	subnetSet := make(map[string]bool)
	for _, nb := range notebooks {
		if nb.subnetID != nil {
			subnetSet[*nb.subnetID] = true
		}
	}
	publicSubnets := make(map[string]bool)
	if len(subnetSet) > 0 {
		var subnetIDs []string
		for id := range subnetSet {
			subnetIDs = append(subnetIDs, id)
		}
		rtResp, err := ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
			Filters: []ec2types.Filter{{
				Name:   aws.String("association.subnet-id"),
				Values: subnetIDs,
			}},
		})
		if err == nil {
			for _, rt := range rtResp.RouteTables {
				hasIGW := false
				for _, route := range rt.Routes {
					if route.GatewayId != nil && strings.HasPrefix(*route.GatewayId, "igw-") {
						hasIGW = true
						break
					}
				}
				if hasIGW {
					for _, assoc := range rt.Associations {
						if assoc.SubnetId != nil {
							publicSubnets[*assoc.SubnetId] = true
						}
					}
				}
			}
		}
	}

	bar := progress.NewBar(ctx, int64(len(notebooks)), "Analyzing SageMaker exposure")
	var findings []audit.Finding

	for _, nb := range notebooks {
		sgOpen := false
		for _, id := range nb.securityGroupIDs {
			if openSGs[id] {
				sgOpen = true
				break
			}
		}
		publicSubnet := nb.subnetID != nil && publicSubnets[*nb.subnetID]

		var risk string
		switch {
		case nb.directInternetAccess:
			risk = "HIGH"
		case publicSubnet && sgOpen:
			risk = "HIGH"
		case publicSubnet:
			risk = "MEDIUM"
		case sgOpen:
			risk = "LOW"
		default:
			risk = "MINIMAL"
		}
		findings = append(findings, audit.Finding{
			Service:    "sagemaker",
			ResourceID: nb.name,
			Check:      "notebook_exposure",
			Status:     statusFromRisk(risk),
			Detail: fmt.Sprintf(
				"status=%s, direct_internet=%t, public_subnet=%t, sg_open=%t",
				nb.status,
				nb.directInternetAccess,
				publicSubnet,
				sgOpen,
			),
			RiskLevel: risk,
		})
		bar.Add(1)
	}
	return findings, nil
}

func listNotebooks(ctx context.Context, cfg aws.Config) ([]sageMakerNotebook, error) {
	client := sagemaker.NewFromConfig(cfg)

	// Collect all notebook names first
	type nbRef struct {
		name string
	}

	var refs []nbRef
	input := &sagemaker.ListNotebookInstancesInput{}
	for {
		resp, err := client.ListNotebookInstances(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list notebook instances: %w", err)
		}
		for _, nb := range resp.NotebookInstances {
			if nb.NotebookInstanceName != nil {
				refs = append(refs, nbRef{name: *nb.NotebookInstanceName})
			}
		}
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}

	// Describe all notebooks concurrently
	results := make([]sageMakerNotebook, len(refs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, audit.GetThresholds(ctx).Concurrency)

	for i, ref := range refs {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			desc, err := client.DescribeNotebookInstance(
				ctx,
				&sagemaker.DescribeNotebookInstanceInput{
					NotebookInstanceName: &name,
				},
			)
			if err != nil {
				results[i] = sageMakerNotebook{} // stays empty, filtered out later
				return
			}
			results[i] = sageMakerNotebook{
				name:                 name,
				status:               string(desc.NotebookInstanceStatus),
				directInternetAccess: string(desc.DirectInternetAccess) == "enabled",
				subnetID:             desc.SubnetId,
				securityGroupIDs:     desc.SecurityGroups,
				roleARN:              desc.RoleArn,
			}
		}(i, ref.name)
	}
	wg.Wait()

	// Filter out empty entries (failed describes)
	var allNBs []sageMakerNotebook
	for _, nb := range results {
		if nb.name != "" {
			allNBs = append(allNBs, nb)
		}
	}
	return allNBs, nil
}
