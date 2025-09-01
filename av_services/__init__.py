def __init__(self, config):
    self.config = config
    
    # DEBUG: Print API key status (remove after testing)
    print("=== API KEY DEBUG ===")
    print(f"VT Key: {'LOADED' if config.get('virustotal_api_key') else 'MISSING'}")
    print(f"HA Key: {'LOADED' if config.get('hybrid_analysis_api_key') else 'MISSING'}")
    print(f"MD Key: {'LOADED' if config.get('metadefender_api_key') else 'MISSING'}")
    print(f"VT Key length: {len(config.get('virustotal_api_key', ''))}")
    print(f"HA Key length: {len(config.get('hybrid_analysis_api_key', ''))}")
    print(f"MD Key length: {len(config.get('metadefender_api_key', ''))}")
    
    # Also check environment variables directly
    import os
    print("=== ENVIRONMENT VARIABLES ===")
    print(f"VIRUSTOTAL_API_KEY: {'SET' if os.environ.get('VIRUSTOTAL_API_KEY') else 'NOT SET'}")
    print(f"HYBRID_ANALYSIS_API_KEY: {'SET' if os.environ.get('HYBRID_ANALYSIS_API_KEY') else 'NOT SET'}")
    print(f"METADEFENDER_API_KEY: {'SET' if os.environ.get('METADEFENDER_API_KEY') else 'NOT SET'}")
    print("============================")