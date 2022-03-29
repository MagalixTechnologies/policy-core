mock:
	mockgen -package mock -destination domain/mock/policies.go github.com/MagalixTechnologies/policy-core/domain PolicyValidationSink
	mockgen -package mock -destination domain/mock/sink.go github.com/MagalixTechnologies/policy-core/domain PoliciesSource
	mockgen -package mock -destination validation/mock/mock.go github.com/MagalixTechnologies/policy-core/validation Validator