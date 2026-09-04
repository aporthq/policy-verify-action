# Changelog

All notable changes to the APort Policy Verify Action will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-09

### Added
- Initial release of APort Policy Verify Action
- Support for `code.repository.merge.v1` policy pack
- Comprehensive GitHub context mapping to APort policy context
- Automatic PR commenting with policy results
- Retry logic with exponential backoff for API reliability
- API key authentication support
- Configurable timeouts and error handling
- Input validation for agent ID and policy pack formats
- Rich PR comments with detailed policy information
- Support for multiple GitHub event triggers
- Manual workflow dispatch capability
- Comprehensive documentation and examples

### Features
- **Policy Enforcement**: Verify PRs against APort agent policies
- **Context Mapping**: Automatic mapping of GitHub context to APort requirements
- **Flexible Configuration**: Customizable policy packs, timeouts, and enforcement rules
- **PR Comments**: Automatic PR comments with policy results and next steps
- **Retry Logic**: Built-in retry mechanism with exponential backoff
- **Authentication**: Support for API key authentication
- **Multiple Triggers**: Support for various GitHub events and manual dispatch
- **Input Validation**: Comprehensive validation of all inputs
- **Error Handling**: Robust error handling with detailed logging

### Technical Details
- **API Integration**: Full integration with APort Policy Verification API
- **Context Fields**: Support for all required policy context fields:
  - `agent_id`, `policy_id`, `idempotency_key`
  - `action`, `repository`, `branch`, `base_branch`
  - `files_changed`, `lines_added`, `lines_removed`, `pr_size_kb`
  - `github_actor`, `github_app`, `requires_review`
  - `labels`, `reviews`, `is_draft`, `is_mergeable`
  - `title`, `description`
- **Response Parsing**: Correct parsing of API response structure
- **Validation**: Joi schema validation for all policy contexts
- **Testing**: Comprehensive test suite with mock API server

### Documentation
- Complete README with setup guide and examples
- Comprehensive example workflows for various use cases
- Troubleshooting guide with common issues and solutions
- API documentation and context mapping reference
- Security best practices and configuration guide

### Examples
- Basic repository protection workflow
- Advanced configuration with custom settings
- Multi-policy verification setup
- Conditional verification based on actor
- Manual dispatch with custom parameters
- Integration with other CI/CD actions
- Environment-specific policy enforcement

## [Unreleased]

### Changed
- Reframed the first public slice as report-only agent attribution and repository provenance.
- Removed required APort account, passport, API key, hosted verifier call, failing enforcement, and default PR comments from the free Action path.
- The Action now writes a GitHub job summary and exits 0.
- Hosted verification payloads now send compact structural findings and avoid duplicate changed-file evidence, keeping repository guard requests within the verifier's hot-path request budget.

### Added
- Automated release workflow for `aporthq/policy-verify-action` that tags the next patch release after a synced PR is merged and updates major/minor convenience tags.
- Conservative PR actor classification: `human`, `known_bot`, `coding_agent`, and `unknown_automation`.
- APort commit trailer recognition for `APort-Session`, `APort-Decision`, and `APort-Agent`.
- Report-only structural findings for protected paths, `pull_request_target`, workflow write-permission escalation, and OIDC token permission changes.
- High-severity suspicious payload findings for encoded execution and remote shell execution introduced in sensitive workflow, action, build-config, policy, verifier, package, or script surfaces.
- High-severity missing-evidence findings when GitHub omits patch/content data for sensitive execution or configuration surfaces.
- Fixture-driven tests with real APortHQ PR payloads and zero false `coding_agent` classifications for human-authored fixtures.

### Security
- Treat `id-token: write` as GitHub OIDC authentication permission, not repository write access. Newly introduced OIDC permission is still reported for review, while broad workflow write permissions remain high-severity.

### Planned Features
- Support for additional policy packs
- Enhanced error reporting and debugging
- Custom policy pack validation
- Integration with GitHub security features
- Advanced context mapping options
- Performance optimizations

---

## Version History

- **1.0.0** - Initial production release with full feature set
- **0.9.0** - Beta release with core functionality
- **0.8.0** - Alpha release with basic policy verification

## Support

For support and questions:
- 📖 [APort](https://aport.io)
- 🚀 [GitHub Actions quickstart](https://aport.io/quickstart/#github)
- 🛡️ [GitHub security guide](https://aport.io/blog/secure-github-actions-ai-coding-agents-protected-paths)
- 🐛 [Issue Tracker](https://github.com/aporthq/policy-verify-action/issues)
- 📧 [Email Support](mailto:support@aport.io)
