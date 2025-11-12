"""
JSON Storage - Simple file-based storage for detection contexts
"""

import json
from pathlib import Path
from typing import List, Optional
from datetime import datetime
from detection_context import DetectionContext


class JSONStorage:
    """
    Simple JSON file storage for detection contexts.
    Each detection is saved as a separate JSON file.
    """
    
    def __init__(self, storage_dir: str = 'detections'):
        """
        Initialize JSON storage
        
        Args:
            storage_dir: Directory to store detection JSON files
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        print(f"[JSONStorage] Initialized storage directory: {self.storage_dir.absolute()}")
    
    def save_detection(self, context: DetectionContext) -> str:
        """
        Save detection context as JSON file
        
        Args:
            context: DetectionContext to save
            
        Returns:
            Path to saved file
        """
        # Create filename with timestamp for easy sorting
        timestamp_str = context.timestamp.strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp_str}_{context.detection_id[:8]}.json"
        filepath = self.storage_dir / filename
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(context.to_json())
        
        print(f"[JSONStorage] Saved detection to: {filepath.name}")
        return str(filepath)
    
    def load_detection(self, detection_id: str) -> Optional[DetectionContext]:
        """
        Load detection context by ID
        
        Args:
            detection_id: Full or partial detection ID
            
        Returns:
            DetectionContext if found, None otherwise
        """
        # Search for file containing this ID
        for filepath in self.storage_dir.glob(f'*{detection_id}*.json'):
            with open(filepath, 'r', encoding='utf-8') as f:
                return DetectionContext.from_json(f.read())
        
        print(f"[JSONStorage] Detection not found: {detection_id}")
        return None
    
    def load_latest(self) -> Optional[DetectionContext]:
        """
        Load the most recent detection
        
        Returns:
            Latest DetectionContext if any exist, None otherwise
        """
        files = sorted(self.storage_dir.glob('*.json'), reverse=True)
        
        if not files:
            print("[JSONStorage] No detections found")
            return None
        
        with open(files[0], 'r', encoding='utf-8') as f:
            return DetectionContext.from_json(f.read())
    
    def load_all_detections(self, limit: Optional[int] = None) -> List[DetectionContext]:
        """
        Load all detection contexts, sorted by timestamp (newest first)
        
        Args:
            limit: Maximum number of detections to load (None = all)
            
        Returns:
            List of DetectionContext objects
        """
        files = sorted(self.storage_dir.glob('*.json'), reverse=True)
        
        if limit:
            files = files[:limit]
        
        detections = []
        for filepath in files:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    detections.append(DetectionContext.from_json(f.read()))
            except Exception as e:
                print(f"[JSONStorage] Error loading {filepath.name}: {e}")
        
        print(f"[JSONStorage] Loaded {len(detections)} detections")
        return detections
    
    def search_by_sender(self, sender_number: str) -> List[DetectionContext]:
        """
        Find all detections from a specific sender
        
        Args:
            sender_number: Phone number to search for
            
        Returns:
            List of DetectionContext objects from this sender
        """
        all_detections = self.load_all_detections()
        
        matches = [
            ctx for ctx in all_detections 
            if ctx.sender_mobile_number == sender_number
        ]
        
        print(f"[JSONStorage] Found {len(matches)} detections from {sender_number}")
        return matches
    
    def search_by_url(self, url: str) -> List[DetectionContext]:
        """
        Find all detections containing a specific URL
        
        Args:
            url: URL to search for
            
        Returns:
            List of DetectionContext objects containing this URL
        """
        all_detections = self.load_all_detections()
        
        matches = [
            ctx for ctx in all_detections 
            if url in ctx.urls_found or url in ctx.expanded_urls.values()
        ]
        
        print(f"[JSONStorage] Found {len(matches)} detections with URL: {url}")
        return matches
    
    def get_statistics(self) -> dict:
        """
        Get statistics about stored detections
        
        Returns:
            Dict with statistics
        """
        all_detections = self.load_all_detections()
        
        if not all_detections:
            return {
                'total_detections': 0,
                'phishing_count': 0,
                'safe_count': 0,
                'uncertain_count': 0
            }
        
        phishing = sum(1 for ctx in all_detections if ctx.final_verdict == 'phishing')
        safe = sum(1 for ctx in all_detections if ctx.final_verdict == 'safe')
        uncertain = sum(1 for ctx in all_detections if ctx.final_verdict == 'uncertain')
        
        return {
            'total_detections': len(all_detections),
            'phishing_count': phishing,
            'safe_count': safe,
            'uncertain_count': uncertain,
            'phishing_rate': phishing / len(all_detections) if all_detections else 0,
            'oldest_detection': all_detections[-1].timestamp.isoformat(),
            'newest_detection': all_detections[0].timestamp.isoformat()
        }
    
    def cleanup_old_detections(self, days: int = 30):
        """
        Delete detections older than specified days
        
        Args:
            days: Delete detections older than this many days
            
        Returns:
            Number of files deleted
        """
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days)
        deleted_count = 0
        
        for filepath in self.storage_dir.glob('*.json'):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    ctx = DetectionContext.from_json(f.read())
                
                if ctx.timestamp < cutoff_date:
                    filepath.unlink()
                    deleted_count += 1
            except Exception as e:
                print(f"[JSONStorage] Error processing {filepath.name}: {e}")
        
        print(f"[JSONStorage] Deleted {deleted_count} old detections")
        return deleted_count
