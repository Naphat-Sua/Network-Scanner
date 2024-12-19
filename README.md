# Network Scanner

A authenticated network monitoring tool for legitimate network administration and security auditing purposes. This tool implements proper authentication, logging, and secure scanning features for authorized network monitoring.

## Features

- User authentication with secure password hashing
- JWT-based token authentication
- Role-based access control
- Comprehensive logging system
- Secure network device discovery
- Continuous network monitoring
- Results storage and audit trail

## Prerequisites

```bash
pip install -r requirements.txt
```

Required packages:
- scapy
- pyjwt
- cryptography
- sqlite3

## Setup

1. Clone the repository
2. Install dependencies
3. Set up the initial admin user:

```python
from network_monitor import Authentication
auth = Authentication()
auth.register_user('admin', 'secure_password', 'admin')
```

## Usage

Basic usage:
```bash
python network_monitor.py -u username -ip 192.168.1.0/24
```

Options:
- `-u, --username`: Authentication username
- `-ip, --ip_range`: IP range to monitor (e.g., 192.168.1.0/24)
- `-i, --interval`: Monitoring interval in seconds (default: 300)

## Security Features

1. **Authentication**:
   - Secure password hashing with salt
   - JWT token-based session management
   - Role-based access control

2. **Logging**:
   - Comprehensive activity logging
   - Audit trail for all scans
   - Error tracking and reporting

3. **Data Security**:
   - Encrypted storage of sensitive data
   - Secure token handling
   - Protected scan results

## Guideline

1. Always run with proper authorization
2. Regularly rotate authentication credentials
3. Monitor the audit logs
4. Use secure passwords
5. Keep the software updated

## Limitations

- Requires proper network permissions
- Should only be used on networks you are authorized to monitor
- Not intended for unauthorized scanning or reconnaissance

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

[Add appropriate license]

## Disclaimer

This tool is for authorized network monitoring only. Users must ensure they have proper authorization before monitoring any network.
