import os
import sys
from django.core.management.base import BaseCommand, CommandError
from django.core.management import call_command

class Command(BaseCommand):
    help = "Run makemigrations, migrate, collectstatic, then runserver (for local dev)."

    def add_arguments(self, parser):
        parser.add_argument('--port', type=int, default=8000, help='Port for runserver')
        parser.add_argument('--addr', type=str, default='127.0.0.1', help='Address for runserver')
        parser.add_argument('--skip-static', action='store_true', help='Skip collectstatic step')
        parser.add_argument('--no-input', action='store_true', help='Pass --noinput to collectstatic')

    def handle(self, *args, **options):
        port = options['port']
        addr = options['addr']
        skip_static = options['skip_static']
        no_input = options['no_input']

        self.stdout.write(self.style.NOTICE('==> makemigrations (all apps)'))
        call_command('makemigrations')

        self.stdout.write(self.style.NOTICE('==> migrate'))
        call_command('migrate')

        if not skip_static:
            self.stdout.write(self.style.NOTICE('==> collectstatic'))
            cs_kwargs = {}
            if no_input:
                cs_kwargs['interactive'] = False
            call_command('collectstatic', **cs_kwargs)

        self.stdout.write(self.style.SUCCESS('==> starting runserver'))
        call_command('runserver', f'{addr}:{port}')
