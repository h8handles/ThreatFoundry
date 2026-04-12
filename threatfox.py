"""
Legacy helper kept only as a pointer to the Django management commands.

The project now uses `python manage.py import_threatfox` as the single ingest
path so we do not maintain two separate entry points that do the same thing.
"""

if __name__ == "__main__":
    print("Use `python manage.py import_threatfox --days 1` instead.")
