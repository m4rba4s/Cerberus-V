#!/usr/bin/env python3
# Test LIVE Manager

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from userspace.live_manager import LiveModeManager, LiveConfig

def test_live_manager():
    print("🧪 Testing LIVE Manager...")
    
    try:
        # Create manager
        config = LiveConfig()
        manager = LiveModeManager(config)
        
        print("✅ Manager created successfully")
        
        # Get status
        status = manager.get_status()
        print(f"📊 Status: {status}")
        
        # Test mode switching
        print("🔄 Testing mode switching...")
        
        # Switch to live mode
        success = manager.enable_live_mode()
        print(f"Live mode enabled: {success}")
        
        # Get status again
        status = manager.get_status()
        print(f"📊 Status after live: {status}")
        
        # Switch back to simulation
        success = manager.disable_live_mode()
        print(f"Simulation mode enabled: {success}")
        
        # Final status
        status = manager.get_status()
        print(f"📊 Final status: {status}")
        
        print("✅ All tests passed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_live_manager() 