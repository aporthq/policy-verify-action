# APort Policy Verify Action

Verify pull requests against APort agent policies to ensure compliance and security.

## 🚀 Features

- **Policy Enforcement** - Verify PRs against APort agent policies
- **GitHub Integration** - Seamless integration with GitHub Actions
- **Context Mapping** - Automatic mapping of GitHub context to APort policies
- **Flexible Configuration** - Customizable policy packs and enforcement rules
- **PR Comments** - Automatic PR comments with policy results
- **Multiple Triggers** - Support for various GitHub events

## 📋 Usage

### Basic Usage

```yaml
name: APort Policy Check
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: APort Policy Verification
        uses: aporthq/policy-verify-action@v1
        with:
          agent-id: ${{ secrets.APORT_AGENT_ID }}
          policy-pack: 'repo.v1'
          fail-on-violation: true
          comment-on-pr: true
```

### Advanced Usage

```yaml
name: Advanced APort Policy Check
on:
  pull_request:
    types: [opened, synchronize, labeled, ready_for_review]
  workflow_dispatch:
    inputs:
      agent_id:
        description: 'Agent ID to verify'
        required: true

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: APort Policy Verification
        uses: aporthq/policy-verify-action@v1
        with:
          agent-id: ${{ github.event.inputs.agent_id || secrets.APORT_AGENT_ID }}
          policy-pack: 'repo.v1'
          api-base: 'https://api.aport.dev'
          fail-on-violation: true
          comment-on-pr: true
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## 🔧 Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `agent-id` | The APort Agent ID to use for policy verification | ✅ | - |
| `policy-pack` | The APort policy pack ID to enforce (e.g., repo.v1) | ✅ | `repo.v1` |
| `api-base` | The base URL for the APort API | ❌ | `https://api.aport.dev` |
| `fail-on-violation` | Whether the action should fail if a policy violation is detected | ❌ | `true` |
| `comment-on-pr` | Whether to add a comment to the pull request with policy results | ❌ | `true` |
| `github-token` | GitHub token for commenting on PRs | ❌ | `${{ github.token }}` |

## 📤 Outputs

| Output | Description |
|--------|-------------|
| `allow` | Boolean indicating if the action is allowed by policy |
| `reasons` | JSON array of reasons for policy violation, if any |

## 🏗️ Setup

### 1. Create APort Agent

1. Go to [APort Dashboard](https://aport.dev)
2. Create a new agent
3. Configure policy settings
4. Note the Agent ID

### 2. Set GitHub Secrets

Add the following secrets to your repository:

```bash
# Required
APORT_AGENT_ID=your-agent-id-here

# Optional (for PR comments)
GITHUB_TOKEN=your-github-token
```

### 3. Configure Agent Passport

In your APort agent passport, set up the following:

```json
{
  "integrations": {
    "github": {
      "allowed_actors": ["your-bot[bot]", "acme-ci"],
      "allowed_apps": ["your-github-app"]
    }
  },
  "capabilities": ["repo.v1"],
  "assurance_level": 3
}
```

## 📊 Policy Packs

### repo.v1 - Repository Safety

Enforces repository-level safety policies:

- **Allowed Repositories** - Restrict which repositories the agent can act on
- **Branch Protection** - Ensure changes go through proper review
- **File Size Limits** - Prevent large file uploads
- **GitHub Actor Validation** - Verify the GitHub actor is authorized
- **GitHub App Validation** - Verify the GitHub app is authorized

## 🔍 Context Mapping

The action automatically maps GitHub context to APort policy context:

| GitHub Context | APort Context | Description |
|----------------|---------------|-------------|
| `github.repository` | `repo` | Repository name |
| `github.event.pull_request.base.ref` | `base_branch` | Target branch |
| `github.actor` | `github_actor` | GitHub actor |
| `github.app` | `github_app` | GitHub app |
| Computed diff stats | `files_changed`, `lines_added` | Change statistics |
| PR labels | `labels` | Pull request labels |
| Review count | `reviews` | Number of reviews |

## 🚨 Troubleshooting

### Common Issues

1. **Agent not found**
   - Verify `APORT_AGENT_ID` is correct
   - Check agent exists in APort dashboard

2. **Policy violations**
   - Review agent passport configuration
   - Check policy pack requirements
   - Verify GitHub actor/app permissions

3. **API errors**
   - Verify `api-base` URL is correct
   - Check network connectivity
   - Review API rate limits

### Debug Mode

Enable debug logging:

```yaml
- name: APort Policy Verification
  uses: aporthq/policy-verify-action@v1
  with:
    agent-id: ${{ secrets.APORT_AGENT_ID }}
    debug: true
```

## 📚 Examples

See the `example-repo/` directory for complete working examples.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🆘 Support

- 📖 [Documentation](https://docs.aport.dev)
- 💬 [Discord Community](https://discord.gg/aport)
- 🐛 [Issue Tracker](https://github.com/aporthq/policy-verify-action/issues)
- 📧 [Email Support](mailto:support@aport.dev)