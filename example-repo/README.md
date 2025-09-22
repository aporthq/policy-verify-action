# APort Policy Verification Example

This repository demonstrates how to use the APort Policy Verification GitHub Action to enforce security policies on pull requests.

## 🚀 Quick Start

### 1. Fork this Repository

Click the "Fork" button to create your own copy of this repository.

### 2. Set up APort Agent

1. Go to [APort Dashboard](https://aport.dev)
2. Create a new agent
3. Configure the agent with the following settings:

```json
{
  "name": "My GitHub Bot",
  "capabilities": ["repo.v1"],
  "assurance_level": 3,
  "integrations": {
    "github": {
      "allowed_actors": ["my-bot[bot]", "acme-ci"],
      "allowed_apps": ["my-github-app"]
    }
  }
}
```

### 3. Configure GitHub Secrets

Add the following secrets to your repository:

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add the following secrets:

| Secret Name | Description | Example Value |
|-------------|-------------|---------------|
| `APORT_AGENT_ID` | Your APort Agent ID | `agent_1234567890abcdef` |

### 4. Test the Action

1. Create a new branch
2. Make some changes
3. Open a pull request
4. The action will automatically run and verify your changes

## 🔧 Configuration

### Agent Passport Settings

Configure your agent passport with the following policy settings:

```json
{
  "integrations": {
    "github": {
      "allowed_actors": ["your-bot[bot]", "acme-ci"],
      "allowed_apps": ["your-github-app"]
    }
  },
  "capabilities": ["repo.v1"],
  "assurance_level": 3,
  "limits": {
    "max_files_changed": 100,
    "max_lines_added": 1000,
    "required_reviews": 1
  }
}
```

### Workflow Configuration

The workflow is configured to run on:

- **Pull Request Events:**
  - `opened` - When a PR is opened
  - `synchronize` - When new commits are pushed
  - `labeled` - When labels are added/removed
  - `ready_for_review` - When PR is marked ready for review

- **Manual Dispatch:**
  - Can be triggered manually with custom agent ID

## 📊 Policy Enforcement

The action enforces the following policies:

### Repository Safety (repo.v1)

- **Allowed Repositories** - Only specified repositories
- **Branch Protection** - Changes must go through proper review
- **File Size Limits** - Prevent large file uploads
- **GitHub Actor Validation** - Verify the GitHub actor is authorized
- **GitHub App Validation** - Verify the GitHub app is authorized

### Example Policy Violations

The action will fail if:

- The GitHub actor is not in the `allowed_actors` list
- The GitHub app is not in the `allowed_apps` list
- Too many files are changed (exceeds `max_files_changed`)
- Too many lines are added (exceeds `max_lines_added`)
- Required reviews are not met

## 🚨 Troubleshooting

### Common Issues

1. **"Agent not found" error**
   - Verify `APORT_AGENT_ID` secret is correct
   - Check agent exists in APort dashboard

2. **"Policy violation" error**
   - Review agent passport configuration
   - Check if GitHub actor is in `allowed_actors`
   - Verify policy limits are appropriate

3. **"API error" error**
   - Check network connectivity
   - Verify API endpoint is accessible
   - Review rate limits

### Debug Mode

To enable debug logging, modify the workflow:

```yaml
- name: APort policy verification
  env:
    APORT_API_BASE: https://api.aport.dev
    APORT_AGENT_ID: ${{ secrets.APORT_AGENT_ID }}
    DEBUG: true  # Add this line
```

## 📚 Examples

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

## 🤝 Contributing

1. Fork this repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🆘 Support

- 📖 [APort Documentation](https://docs.aport.dev)
- 💬 [Discord Community](https://discord.gg/aport)
- 🐛 [Issue Tracker](https://github.com/aporthq/policy-verify-action/issues)
- 📧 [Email Support](mailto:support@aport.dev)

## 🔗 Related

- [APort Dashboard](https://aport.dev)
- [Policy Verify Action](https://github.com/aporthq/policy-verify-action)
- [APort Documentation](https://docs.aport.dev)