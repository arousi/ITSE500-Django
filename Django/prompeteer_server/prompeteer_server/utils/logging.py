# --- Custom log formatter for A4 wrapping ---
import logging
import textwrap
import json
import re
import copy


class A4WrapFormatter(logging.Formatter):
    def mask_tokens_in_dict(self, d):
        d = copy.deepcopy(d)
        for key in ['access_token', 'refresh_token']:
            if key in d and d[key]:
                d[key] = d[key][:20] + '...'
        return d

    def pretty_dict(self, d):
        # Only pretty-print if it's a dict
        if isinstance(d, dict):
            return json.dumps(self.mask_tokens_in_dict(d), indent=4, ensure_ascii=False)
        return str(d)

    def mask_and_pretty(self, msg):
        # Try to find dict-like substrings and pretty-print them
        # This is a simple regex for {...} at end of line or after resp=
        def replacer(match):
            try:
                d = eval(match.group(0))
                return '\n' + self.pretty_dict(d)
            except Exception:
                return match.group(0)
        # Replace dicts after resp= or data=
        msg = re.sub(r'(resp|data)=({[\s\S]*?})', lambda m: m.group(1)+'='+replacer(m), msg)
        return msg

    def format(self, record):
        msg = super().format(record)
        msg = self.mask_and_pretty(msg)
        # Split at 100 chars for A4 width
        lines = []
        for line in msg.splitlines():
            lines.extend(textwrap.wrap(line, width=100, replace_whitespace=False, drop_whitespace=False))
        return '\n'.join(lines)