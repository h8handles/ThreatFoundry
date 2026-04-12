from django.conf import settings
from django.core.management.commands.runserver import Command as DjangoRunserverCommand


class Command(DjangoRunserverCommand):
    """
    Make the local dev server default to LAN-friendly settings for this project.

    You can still override these by passing an explicit address/port, for example:
    `python manage.py runserver 127.0.0.1:9000`
    """

    default_addr = settings.RUNSERVER_HOST
    default_port = settings.RUNSERVER_PORT

    def handle(self, *args, **options):
        if not options.get("addrport"):
            options["addrport"] = f"{self.default_addr}:{self.default_port}"
        return super().handle(*args, **options)
