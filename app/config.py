"""Application configuration (contains deliberate demo weaknesses)."""
import os

DEBUG = os.getenv("APP_DEBUG", "0") == "1"

DEMO_API_TOKEN = "changeme"

LEGACY_INTERNAL_API_KEY = "a8f3k29dj4h7s1x0q9w2e8r5t6y7u3i4"