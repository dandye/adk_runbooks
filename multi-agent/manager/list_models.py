#!/usr/bin/env python3
"""
ADK Runbooks Model List Utility

This script fetches and displays the available Gemini models from the Google API.
Useful for users to see what models they can configure in their .env file.

Usage:
    python list_models.py
    
Make sure GOOGLE_API_KEY is set in your .env file or environment.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add the parent directory to the path so we can import from tools
sys.path.append(str(Path(__file__).parent))

# Import just the function we need
import os
import requests

def fetch_available_models(api_key):
    """Fetches available models from the Google Gemini API.
    
    Args:
        api_key (str): Google API key for authentication
        
    Returns:
        list: List of available model names, or None if fetch fails
    """
    try:
        url = "https://generativelanguage.googleapis.com/v1beta/models"
        params = {
            'key': api_key,
            'pageSize': 100  # Get more models in one request
        }
        
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        models = data.get('models', [])
        
        # Extract model names and filter for text generation models
        model_names = []
        for model in models:
            name = model.get('name', '')
            if name.startswith('models/'):
                model_name = name.replace('models/', '')
                # Filter for text generation models (exclude image/video generation)
                if any(keyword in model_name.lower() for keyword in ['gemini', 'text', 'chat']):
                    model_names.append(model_name)
        
        return sorted(model_names)
        
    except Exception as e:
        print(f"⚠️ Could not fetch models from API: {e}")
        return None

def main():
    """Main function to fetch and display available models."""
    
    # Load environment variables
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        print(f"✓ Loaded environment from {env_path}")
    else:
        print(f"⚠️ No .env file found at {env_path}")
        print("   Create .env from .env.example and add your GOOGLE_API_KEY")
    
    # Get API key
    api_key = os.getenv('GOOGLE_API_KEY')
    if not api_key:
        print("❌ GOOGLE_API_KEY not found in environment variables")
        print("   Please set GOOGLE_API_KEY in your .env file")
        print("   Get your key from: https://makersuite.google.com/app/apikey")
        sys.exit(1)
    
    if not api_key.startswith('AI'):
        print("⚠️ API key doesn't look like a valid Google AI key (should start with 'AI')")
    
    print(f"\n🔍 Fetching available models from Google Gemini API...")
    
    # Fetch models
    models = fetch_available_models(api_key)
    
    if models is None:
        print("❌ Failed to fetch models from API")
        print("   Check your internet connection and API key")
        sys.exit(1)
    
    if not models:
        print("⚠️ No models returned from API")
        sys.exit(1)
    
    # Display results
    print(f"\n✅ Found {len(models)} available models:\n")
    
    # Group models by generation for better display
    model_groups = {}
    for model in models:
        if 'gemini-2.5' in model:
            group = "Gemini 2.5 (Latest)"
        elif 'gemini-2.0' in model:
            group = "Gemini 2.0"
        elif 'gemini-1.5' in model:
            group = "Gemini 1.5"
        elif 'gemini-1.0' in model:
            group = "Gemini 1.0"
        else:
            group = "Other"
        
        if group not in model_groups:
            model_groups[group] = []
        model_groups[group].append(model)
    
    # Display grouped models
    for group, group_models in model_groups.items():
        print(f"📋 {group}:")
        for model in sorted(group_models):
            print(f"   • {model}")
        print()
    
    # Show configuration example
    print("💡 To use a specific model, add this to your .env file:")
    print(f"   ADK_MODEL={models[0]}")
    print(f"\n   Example for latest Gemini 2.5:")
    gemini_25_models = [m for m in models if 'gemini-2.5' in m]
    if gemini_25_models:
        print(f"   ADK_MODEL={gemini_25_models[0]}")

if __name__ == "__main__":
    main()