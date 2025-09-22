# GitHub Marketplace Publishing Guide

This guide explains how to publish the APort Action to the GitHub Marketplace.

## 📋 Prerequisites

1. **GitHub Account** with appropriate permissions
2. **Action Repository** (e.g., `aporthq/github-actions`)
3. **Valid action.yml** file (already created)
4. **Repository Secrets** for deployment

## 🏗️ Repository Structure

For a single action repository, use this structure:

```
aporthq/github-actions/
├── action.yml                 # Main action definition
├── README.md                  # Action documentation
├── .github/
│   └── workflows/
│       └── test.yml          # Test workflow
└── examples/
    └── example-repo/         # Example usage
        ├── .github/workflows/
        │   └── aport-verify.yml
        └── README.md
```

## 🚀 Publishing Steps

### 1. Create Action Repository

```bash
# Create new repository
gh repo create aporthq/github-actions --public --description "APort Policy Verification GitHub Action"

# Clone and setup
git clone https://github.com/aporthq/github-actions.git
cd github-actions
```

### 2. Set up Repository Secrets

Add these secrets to your action repository:

- `GITHUB_TOKEN`: For automated deployments
- `APORT_API_KEY`: For testing (optional)

### 3. Deploy Action Files

Use the deployment workflow to push files:

```bash
# Trigger deployment workflow
gh workflow run deploy-action.yml --ref main
```

### 4. Create First Release

```bash
# Create initial release
git tag v1.0.0
git push origin v1.0.0

# Or use GitHub CLI
gh release create v1.0.0 --title "APort Action v1.0.0" --notes "Initial release"
```

### 5. Publish to Marketplace

1. Go to your repository on GitHub
2. Click on "Actions" tab
3. Click on "Marketplace" in the left sidebar
4. Click "Publish this Action"
5. Fill out the marketplace form:

```yaml
# Marketplace form fields
Name: APort Policy Verification
Description: Verify pull requests against APort agent policies for enhanced security
Category: Security
Keywords: security, policy, verification, agent, bot, compliance
Pricing: Free
```

## 📝 Action.yml Requirements

The action.yml file must include:

```yaml
name: 'APort Policy Verification'
description: 'Verify pull requests against APort agent policies for enhanced security'
author: 'APort Team'
branding:
  icon: 'shield'
  color: 'blue'

# Required for marketplace
runs:
  using: 'composite'  # or 'node16' for JavaScript actions
  steps: [...]
```

## 🧪 Testing Before Publishing

### 1. Local Testing

```bash
# Test the action locally
act -j test-action
```

### 2. Repository Testing

Create a test repository with the action:

```yaml
# .github/workflows/test-aport.yml
name: Test APort Action
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aporthq/github-actions@v1
        with:
          agent-id: ${{ secrets.APORT_AGENT_ID }}
```

### 3. Integration Testing

Test with real APort API:

```bash
# Set up test agent
export APORT_AGENT_ID="agt_test_123"
export APORT_API_BASE="https://api.aport.dev"

# Run test
npm test
```

## 📊 Marketplace Optimization

### 1. SEO-Friendly Description

```markdown
# APort Policy Verification

🛡️ **Secure your repositories with AI agent verification**

APort Policy Verification ensures only authorized AI agents and bots can make changes to your repositories. Perfect for:

- 🤖 Bot security and verification
- 🏢 Enterprise compliance
- 🔒 Multi-repository policy management
- 📊 Audit trail and monitoring

## Features

- ✅ Agent identity verification
- 🎯 Policy-based access control
- 📈 Real-time monitoring
- 🔄 Easy integration
- 📚 Comprehensive documentation

## Quick Start

1. Set `APORT_AGENT_ID` secret
2. Add the action to your workflow
3. Configure policies in APort dashboard

[Get started →](https://docs.aport.dev)
```

### 2. Keywords for Discovery

```
security, policy, verification, agent, bot, compliance, 
github-actions, ci-cd, automation, devops, audit, 
access-control, identity, authentication, authorization
```

### 3. Screenshots and GIFs

Create visual content:
- Action in workflow editor
- Policy verification results
- Dashboard screenshots
- Integration examples

## 🔄 Release Management

### Versioning Strategy

```bash
# Semantic versioning
v1.0.0  # Initial release
v1.1.0  # New features
v1.1.1  # Bug fixes
v2.0.0  # Breaking changes
```

### Automated Releases

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Create Release
        uses: actions/create-release@v1
        with:
          tag_name: ${{ github.ref }}
          release_name: Release ${{ github.ref }}
          body: |
            ## Changes in this Release
            - Feature 1
            - Feature 2
            - Bug fixes
```

## 📈 Analytics and Monitoring

### 1. Usage Analytics

Track action usage:
- Downloads per version
- Repository adoption
- Error rates
- Performance metrics

### 2. User Feedback

- GitHub Issues for bug reports
- Discussions for feature requests
- Star and fork tracking
- Community engagement

### 3. Success Metrics

- Number of repositories using the action
- Monthly active users
- Issue resolution time
- Community contributions

## 🛠️ Maintenance

### 1. Regular Updates

- Security patches
- GitHub Actions updates
- API compatibility
- Documentation updates

### 2. Community Support

- Respond to issues quickly
- Provide clear documentation
- Create examples and tutorials
- Engage with users

### 3. Monitoring

- Watch for breaking changes
- Monitor API deprecations
- Track security vulnerabilities
- Update dependencies

## 🎯 Marketing Strategy

### 1. Content Marketing

- Blog posts about bot security
- Tutorial videos
- Case studies
- Webinars

### 2. Community Engagement

- GitHub Discussions
- Twitter/LinkedIn posts
- Dev.to articles
- Conference talks

### 3. Partnerships

- GitHub partnership program
- Enterprise partnerships
- Integration partnerships
- Community collaborations

## 📚 Documentation

### 1. README.md

Include:
- Quick start guide
- Configuration options
- Examples
- Troubleshooting
- Contributing guidelines

### 2. API Documentation

- Input parameters
- Output values
- Error handling
- Best practices

### 3. Examples

- Basic usage
- Advanced configuration
- Integration patterns
- Real-world use cases

## 🔒 Security Considerations

### 1. Secret Management

- Never expose API keys
- Use GitHub secrets
- Rotate keys regularly
- Monitor access logs

### 2. Code Security

- Regular security audits
- Dependency updates
- Vulnerability scanning
- Secure coding practices

### 3. User Privacy

- Minimal data collection
- Clear privacy policy
- GDPR compliance
- Data retention policies

## 📞 Support

### 1. Documentation

- Comprehensive guides
- FAQ section
- Troubleshooting guides
- Video tutorials

### 2. Community

- GitHub Discussions
- Discord server
- Stack Overflow
- Reddit community

### 3. Enterprise Support

- Priority support
- Custom integrations
- Training sessions
- SLA agreements

---

**Ready to publish? Follow these steps and your APort Action will be live on the GitHub Marketplace! 🚀**
