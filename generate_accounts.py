"""Run the interactive MIDx guest generator in its own protobuf process."""
import os, sys
from pathlib import Path
os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')
if __name__ == '__main__':
    from google_dns import install as _install_google_dns
    _install_google_dns()
from br_engine import generate_accounts_interactive
if __name__ == '__main__':
    made=generate_accounts_interactive()
    print(f'\n  Generated {len(made)} account(s). Guilds are not joined automatically.')
