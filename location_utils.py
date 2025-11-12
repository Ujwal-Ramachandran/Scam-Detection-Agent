"""
Location Utilities - Get host location and phone number information
"""

import geocoder
import phonenumbers
from phonenumbers import geocoder as phone_geocoder, carrier
from typing import Optional, Dict


def get_host_location() -> Optional[Dict]:
    """
    Get location of current host using geocoder library
    
    Returns:
        Dict with location information or None if failed
        {
            'ip': str,
            'city': str,
            'country': str,
            'country_code': str,
            'latitude': float,
            'longitude': float,
            'timezone': str
        }
    """
    try:
        # Get location based on IP
        g = geocoder.ip('me')
        
        if g.ok:
            location = {
                'ip': g.ip,
                'city': g.city,
                'country': g.country,
                'country_code': g.country,  # geocoder uses country code here
                'latitude': g.lat,
                'longitude': g.lng,
                'timezone': None  # geocoder doesn't provide timezone
            }
            
            print(f"[LocationUtils] Host location: {location['city']}, {location['country']}")
            return location
        else:
            print("[LocationUtils] Failed to get host location")
            return None
            
    except Exception as e:
        print(f"[LocationUtils] Error getting host location: {e}")
        return None


def get_phone_info(phone_number: str) -> Optional[Dict]:
    """
    Get country and carrier information from phone number
    
    Args:
        phone_number: Phone number string (with or without country code)
        
    Returns:
        Dict with phone information or None if failed
        {
            'country': str,
            'country_code': str,
            'carrier': str,
            'is_valid': bool,
            'number_type': str,  # 'MOBILE', 'FIXED_LINE', 'TOLL_FREE', etc.
            'formatted': str     # International format
        }
    """
    try:
        # Parse the phone number
        # If no country code, try to parse as international
        parsed = None
        
        # Try parsing as-is first
        try:
            parsed = phonenumbers.parse(phone_number, None)
        except phonenumbers.NumberParseException:
            # If fails, try with + prefix
            if not phone_number.startswith('+'):
                try:
                    parsed = phonenumbers.parse('+' + phone_number, None)
                except:
                    pass
        
        if not parsed:
            print(f"[LocationUtils] Could not parse phone number: {phone_number}")
            return None
        
        # Get information
        country = phone_geocoder.description_for_number(parsed, "en")
        carrier_name = carrier.name_for_number(parsed, "en")
        is_valid = phonenumbers.is_valid_number(parsed)
        
        # Get number type
        number_type_code = phonenumbers.number_type(parsed)
        number_type_map = {
            0: 'FIXED_LINE',
            1: 'MOBILE',
            2: 'FIXED_LINE_OR_MOBILE',
            3: 'TOLL_FREE',
            4: 'PREMIUM_RATE',
            5: 'SHARED_COST',
            6: 'VOIP',
            7: 'PERSONAL_NUMBER',
            8: 'PAGER',
            9: 'UAN',
            10: 'VOICEMAIL',
            99: 'UNKNOWN'
        }
        number_type = number_type_map.get(number_type_code, 'UNKNOWN')
        
        # Get formatted number
        formatted = phonenumbers.format_number(
            parsed, 
            phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )
        
        # Get country code
        country_code = f"+{parsed.country_code}"
        
        phone_info = {
            'country': country if country else 'Unknown',
            'country_code': country_code,
            'carrier': carrier_name if carrier_name else 'Unknown',
            'is_valid': is_valid,
            'number_type': number_type,
            'formatted': formatted
        }
        
        print(f"[LocationUtils] Phone info: {phone_info['country']}, {phone_info['carrier']}, {phone_info['number_type']}")
        return phone_info
        
    except Exception as e:
        print(f"[LocationUtils] Error getting phone info: {e}")
        return None

def check_location_mismatch(host_location: Optional[Dict], 
                           phone_info: Optional[Dict]) -> bool:
    """
    Check if there's a suspicious location mismatch between host and sender
    
    Args:
        host_location: Host location dict from get_host_location()
        phone_info: Phone info dict from get_phone_info()
        
    Returns:
        True if there's a suspicious mismatch, False otherwise
    """
    if not host_location or not phone_info:
        return False
    
    # Compare countries
    host_country = host_location.get('country', '').lower()
    phone_country = phone_info.get('country', '').lower()
    
    if host_country and phone_country:
        # If countries are different, it might be suspicious
        # (though not always - legitimate international messages exist)
        if host_country != phone_country:
            print(f"[LocationUtils] Location mismatch: Host={host_country}, Sender={phone_country}")
            return True
    
    return False


# Example usage and testing
if __name__ == "__main__":
    print("=== Testing Location Utils ===\n")
    
    # Test host location
    print("1. Getting host location...")
    location = get_host_location()
    if location:
        print(f"   Success: {location}\n")
    else:
        print("   Failed to get location\n")
    
    # Test phone number parsing
    print("2. Testing phone number parsing...")
    test_numbers = [
        "+919876543210",  # India
        "+14155552671",   # USA
        "+442071234567",  # UK
        "9876543210",     # Without country code
    ]
    
    for number in test_numbers:
        print(f"\n   Testing: {number}")
        info = get_phone_info(number)
        if info:
            print(f"   Country: {info['country']}")
            print(f"   Carrier: {info['carrier']}")
            print(f"   Type: {info['number_type']}")
            print(f"   Valid: {info['is_valid']}")
            print(f"   Formatted: {info['formatted']}")
    
    # Test location mismatch
    print("\n3. Testing location mismatch detection...")
    if location:
        test_phone = get_phone_info("+919876543210")
        if test_phone:
            mismatch = check_location_mismatch(location, test_phone)
            print(f"   Mismatch detected: {mismatch}")
