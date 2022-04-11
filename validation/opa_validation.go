package validation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	opa "github.com/MagalixTechnologies/opa-core"
	"github.com/MagalixTechnologies/policy-core/domain"
	"github.com/MagalixTechnologies/uuid-go"
	multierror "github.com/hashicorp/go-multierror"
)

const (
	PolicyQuery = "violation"
	maxWorkers  = 25
)

type OpaValidator struct {
	policiesSource  domain.PoliciesSource
	resultsSinks    []domain.PolicyValidationSink
	writeCompliance bool
	validationType  string
}

// NewOPAValidator returns an opa validator to validate entities
func NewOPAValidator(
	policiesSource domain.PoliciesSource,
	writeCompliance bool,
	validationType string,
	resultsSinks ...domain.PolicyValidationSink,
) *OpaValidator {
	return &OpaValidator{
		policiesSource:  policiesSource,
		resultsSinks:    resultsSinks,
		writeCompliance: writeCompliance,
		validationType:  validationType,
	}
}

// Validate validate policies using opa library, implements validation.Validator
func (v *OpaValidator) Validate(ctx context.Context, entity domain.Entity, trigger string) (*domain.PolicyValidationSummary, error) {
	policies, err := v.policiesSource.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to get policies from source: %w", err)
	}

	var enqueueGroup sync.WaitGroup
	var dequeueGroup sync.WaitGroup
	violationsChan := make(chan domain.PolicyValidation, len(policies))
	compliancesChan := make(chan domain.PolicyValidation, len(policies))
	errsChan := make(chan error, len(policies))
	bound := make(chan struct{}, maxWorkers)

	for i := range policies {
		bound <- struct{}{}
		enqueueGroup.Add(1)
		go (func(index int) {
			defer func() {
				<-bound
				enqueueGroup.Done()
			}()
			policy := policies[index]
			if !matchEntity(entity, policy) {
				return
			}
			opaPolicy, err := opa.Parse(policy.Code, PolicyQuery)
			if err != nil {
				errsChan <- fmt.Errorf("failed to parse policy %s: %w", policy.ID, err)
				return
			}

			var opaErr opa.OPAError
			parameters := policy.GetParametersMap()
			err = opaPolicy.EvalGateKeeperCompliant(entity.Manifest, parameters, PolicyQuery)
			if err != nil {
				if errors.As(err, &opaErr) {
					details := opaErr.GetDetails()
					var violations []map[string]interface{}
					if arr, ok := details.([]interface{}); ok {
						for _, item := range arr {
							if violation, ok := item.(map[string]interface{}); ok {
								violations = append(violations, violation)
							}
						}
					} else if m, ok := details.(map[string]interface{}); ok {
						violations = append(violations, m)
					} else {
						violations = append(violations, map[string]interface{}{})
					}

					for _, violation := range violations {
						var title string
						if msg, ok := violation["msg"]; ok {
							title = msg.(string)
						} else {
							title = policy.Name
						}

						message := fmt.Sprintf("%s in %s %s. Policy: %s", title, entity.Kind, entity.Name, policy.ID)

						result := domain.PolicyValidation{
							ID:        uuid.NewV4().String(),
							Policy:    policy,
							Entity:    entity,
							Type:      v.validationType,
							Trigger:   trigger,
							CreatedAt: time.Now(),
							Message:   message,
							Status:    domain.PolicyValidationStatusViolating,
							Details:   violation,
						}

						violationsChan <- result
					}

				} else {
					errsChan <- fmt.Errorf(
						"unable to evaluate resource against policy. policy id: %s. %w",
						policy.ID,
						err)
				}

			} else {
				result := domain.PolicyValidation{
					ID:        uuid.NewV4().String(),
					Policy:    policy,
					Entity:    entity,
					Type:      v.validationType,
					Trigger:   trigger,
					CreatedAt: time.Now(),
					Status:    domain.PolicyValidationStatusCompliant,
				}
				compliancesChan <- result
			}
		})(i)
	}
	violations := make([]domain.PolicyValidation, 0)
	dequeueGroup.Add(1)
	go func() {
		defer dequeueGroup.Done()
		for violation := range violationsChan {
			violations = append(violations, violation)
		}
	}()

	compliances := make([]domain.PolicyValidation, 0)
	dequeueGroup.Add(1)
	go func() {
		defer dequeueGroup.Done()
		for compliance := range compliancesChan {
			compliances = append(compliances, compliance)
		}
	}()

	var errs error
	dequeueGroup.Add(1)
	go func() {
		defer dequeueGroup.Done()
		for chanErr := range errsChan {
			errs = multierror.Append(errs, chanErr)
		}
	}()

	enqueueGroup.Wait()
	close(violationsChan)
	close(compliancesChan)
	close(errsChan)
	dequeueGroup.Wait()

	if errs != nil {
		return nil, fmt.Errorf(
			"encountered errors while validating policies against resource %s/%s: %w",
			entity.Kind,
			entity.Name,
			errs)
	}

	PolicyValidationSummary := domain.PolicyValidationSummary{
		Violations:  violations,
		Compliances: compliances,
	}
	writeToSinks(ctx, v.resultsSinks, PolicyValidationSummary, v.writeCompliance)

	return &PolicyValidationSummary, nil
}
