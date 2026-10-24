# music_utils.py — Lấy và Stream file nhạc từ Google Drive
import os
import requests
from datetime import datetime

GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '').strip()
FOLDER_ID = '1u4QxUZaicCqOIxCFy5Q-XJe-erD0HSOO'

# Cache danh sách nhạc (tránh gọi API nhiều lần)
_cache = {
    'data': None,
    'time': None,
}
CACHE_TTL = 300  # 5 phút


def has_google_api():
    """Kiểm tra có API key chưa."""
    return bool(GOOGLE_API_KEY)


def list_music_files(force_refresh=False):
    """
    Lấy danh sách file audio từ Google Drive folder.
    Trả về list dict: [{id, name, size, size_mb, modified}, ...]
    """
    if not has_google_api():
        return {'success': False, 'error': 'Chưa có GOOGLE_API_KEY'}

    # Cache
    if not force_refresh and _cache['data'] and _cache['time']:
        elapsed = (datetime.now() - _cache['time']).total_seconds()
        if elapsed < CACHE_TTL:
            return {'success': True, 'files': _cache['data'], 'cached': True,
                    'total': len(_cache['data'])}

    try:
        url = 'https://www.googleapis.com/drive/v3/files'
        params = {
            'q': f"'{FOLDER_ID}' in parents and trashed=false",
            'key': GOOGLE_API_KEY,
            'fields': 'files(id,name,mimeType,size,modifiedTime)',
            'pageSize': 200,
            'orderBy': 'name',
        }

        res = requests.get(url, params=params, timeout=15)
        res.raise_for_status()
        data = res.json()

        files = []
        for f in data.get('files', []):
            name = f.get('name', '')
            mime = f.get('mimeType', '')

            # Chỉ lấy file audio
            if 'audio' not in mime and not name.lower().endswith(('.mp3', '.m4a', '.wav', '.ogg')):
                continue

            size = int(f.get('size', 0))
            files.append({
                'id': f['id'],
                'name': name,
                'size': size,
                'size_mb': round(size / (1024 * 1024), 1),
                'modified': f.get('modifiedTime', ''),
                'mime': mime,
            })

        _cache['data'] = files
        _cache['time'] = datetime.now()

        return {'success': True, 'files': files, 'cached': False, 'total': len(files)}

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else '?'
        if status == 403:
            return {'success': False, 'error': 'API Key bị từ chối (403). Kiểm tra lại key hoặc bật Google Drive API.'}
        elif status == 404:
            return {'success': False, 'error': 'Folder không tồn tại (404).'}
        return {'success': False, 'error': f'Google API lỗi {status}'}
    except Exception as e:
        return {'success': False, 'error': f'Lỗi: {str(e)}'}


def get_file_info(file_id):
    """Lấy thông tin 1 file theo ID."""
    if not has_google_api():
        return {'success': False, 'error': 'Chưa có GOOGLE_API_KEY'}

    try:
        url = f'https://www.googleapis.com/drive/v3/files/{file_id}'
        params = {
            'key': GOOGLE_API_KEY,
            'fields': 'id,name,mimeType,size',
        }
        res = requests.get(url, params=params, timeout=10)
        res.raise_for_status()
        return {'success': True, 'file': res.json()}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def stream_file(file_id, range_header=None):
    """
    Stream file audio từ Google Drive.
    Xử lý cả trường hợp Google chèn trang xác nhận (file lớn).
    """
    if not has_google_api():
        return None

    try:
        # Bước 1: Gọi thử để lấy thông tin (có thể bị chặn bởi trang xác nhận)
        url = f'https://www.googleapis.com/drive/v3/files/{file_id}'
        params = {
            'alt': 'media',
            'key': GOOGLE_API_KEY,
            'acknowledgeAbuse': 'true'
        }
        headers = {}
        if range_header:
            headers['Range'] = range_header

        res = requests.get(url, params=params, headers=headers, stream=True, timeout=30)
        
        content_type = res.headers.get('Content-Type', '')

        # Nếu Google trả về HTML (trang cảnh báo / xác nhận)
        if 'text/html' in content_type:
            print(f"⚠️ Google Drive trả về HTML. Thử bypass xác nhận...")
            
            # Lấy token xác nhận từ HTML (nếu có)
            import re
            html_content = res.text
            match = re.search(r'confirm=([^&;\"\']+)', html_content)
            
            if match:
                confirm_token = match.group(1)
                print(f"🔑 Tìm thấy token xác nhận: {confirm_token}")
                
                # Gọi lại với token xác nhận
                bypass_url = f'https://www.googleapis.com/drive/v3/files/{file_id}'
                bypass_params = {
                    'alt': 'media',
                    'key': GOOGLE_API_KEY,
                    'confirm': confirm_token,
                    'acknowledgeAbuse': 'true'
                }
                res2 = requests.get(bypass_url, params=bypass_params, headers=headers, stream=True, timeout=30)
                if res2.status_code in (200, 206):
                    return res2
                else:
                    print(f"⚠️ Bypass thất bại: {res2.status_code}")
                    return None
            else:
                print(f"❌ Không tìm thấy token xác nhận. Google có thể đã chặn hoàn toàn.")
                return None

        # Nếu là file audio bình thường
        if res.status_code in (200, 206):
            return res
        else:
            print(f"⚠️ Google Drive trả về lỗi: {res.status_code}")
            return None
    except Exception as e:
        print(f'❌ Stream error: {e}')
        return None
