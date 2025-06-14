# 🔐 Decentralized KYC Registry

A blockchain-based Know Your Customer (KYC) registry that enables secure, verifiable identity verification with user-controlled permissions for third-party applications.

## 🌟 Features

- **🏛️ Decentralized Verification**: Authorized verifiers can submit KYC records
- **👤 User Control**: Users maintain full control over their data permissions  
- **🔒 Privacy-First**: Only hashed data stored on-chain, original data stays private
- **⏰ Time-Based Permissions**: Configurable expiration for both KYC records and app access
- **📊 Verification Levels**: 5-tier verification system (1-5) for different compliance needs
- **🛡️ Secure Access**: Apps can only query data with explicit user permission

## 🚀 Quick Start

### Prerequisites
- Clarinet installed
- Stacks wallet for testing

### Installation

```bash
git clone <your-repo>
cd kyc-registry
clarinet check
```

## 📋 Contract Functions

### 🔧 Admin Functions
- `authorize-verifier` - Add authorized KYC verifiers
- `revoke-verifier` - Remove verifier authorization
- `toggle-contract-status` - Enable/disable contract

### 🏢 Verifier Functions  
- `submit-kyc-verification` - Submit KYC verification for users
- `revoke-kyc-verification` - Revoke existing KYC records

### 📱 App Functions
- `register-app` - Register application to access KYC data
- `query-kyc-with-permission` - Query user KYC data (with permission)

### 👥 User Functions
- `grant-app-permission` - Grant app access to your KYC data
- `revoke-app-permission` - Revoke app access permissions
- `revoke-kyc-verification` - Revoke your own KYC record

### 🔍 Read-Only Functions
- `check-kyc-status` - Check if user meets KYC requirements
- `get-kyc-record` - Get user's KYC record details
- `is-kyc-valid` - Validate KYC status and level
- `has-valid-permission` - Check app permission status

## 🎯 Usage Examples

### Register as Verifier (Admin Only)
```clarity
(contract-call? .kyc-registry authorize-verifier 'SP1234... u3)
```

### Submit KYC Verification (Verifiers Only)
```clarity
(contract-call? .kyc-registry submit-kyc-verification 
  'SP5678... 
  u2 
  0x1234567890abcdef... 
  u52560)
```

### Register Your App
```clarity
(contract-call? .kyc-registry register-app "MyDeFiApp")
```

### Grant App Permission (Users)
```clarity
(contract-call? .kyc-registry grant-app-permission 
  'SP9999... 
  u2 
  u26280)
```

### Query KYC Data (Apps)
```clarity
(contract-call? .kyc-registry query-kyc-with-permission 
  'SP5678... 
  u2)
```

## 🏗️ Verification Levels

| Level | Description |
|-------|-------------|
| 1 | Basic identity verification |
| 2 | Enhanced identity + address |
| 3 | Full KYC with income verification |
| 4 | Institutional grade verification |
| 5 | Maximum compliance verification |

## 🔒 Security Features

- **Multi-signature Support**: Contract owner controls verifier authorization
- **Time-based Expiration**: All permissions and verifications have expiry
- **Granular Access Control**: Users control exactly what apps can access
- **Data Privacy**: Only cryptographic hashes stored on-chain
- **Revocation Support**: Users and verifiers can revoke records anytime

## 🧪 Testing

```bash
clarinet test
```

## 📄 License

MIT License - Build the future of decentralized identity! 🚀

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

*Built with ❤️ for a more decentralized future*
```

**Git Commit Message:**
```
feat: implement decentralized KYC registry with user-controlled permissions
```

**GitHub Pull Request Title:**
```
🔐 Add Decentralized KYC Registry MVP
```

**GitHub Pull Request Description:**
```
## 🎯 Summary
Implements a complete decentralized KYC registry system that allows users to maintain control over their verification data while enabling compliant third-party access.

## ✨ What's Added
- **Core KYC Registry Contract** with 5-tier verification levels
- **User Permission System** for granular access control  
- **Authorized Verifier Management** with role-based permissions
- **App Registration System** for third-party integrations
- **Time-based Expiration** for all permissions and verifications
- **Privacy-first Design** storing only cryptographic
