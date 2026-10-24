# music_utils.py — Lấy và Stream file nhạc từ Google Drive
import os
import re
import requests
from datetime import datetime

GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '').strip()
FOLDER_ID = '1u4QxUZaicCqOIxCFy5Q-XJe-erD0HSOO'

_cache = {'data': None, 'time': None}
CACHE_TTL = 300  # 5 phút


def has_google_api():
    return bool(GOOGLE_API_KEY)


def list_music_files(force_refresh=False):
    if not has_google_api():
        return {'success': False, 'error': 'Chưa có GOOGLE_API_KEY'}

    if not force_refresh and _cache['data'] and _cache['time']:
        elapsed = (datetime.now() - _cache['time']).total_seconds()
        if elapsed < CACHE_TTL:
            return {'success': True, 'files': _cache['data'], 'cached': True, 'total': len(_cache['data'])}

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
            if 'audio' not in mime and not name.lower().endswith(('.mp3', '.m4a', '.wav', '.ogg')):
                continue
            size = int(f.get('size', 0))
            files.append({
                'id': f['id'], 'name': name, 'size': size,
                'size_mb': round(size / (1024 * 1024), 1),
                'modified': f.get('modifiedTime', ''), 'mime': mime,
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
    if not has_google_api():
        return {'success': False, 'error': 'Chưa có GOOGLE_API_KEY'}
    try:
        url = f'https://www.googleapis.com/drive/v3/files/{file_id}'
        res = requests.get(url, params={'key': GOOGLE_API_KEY, 'fields': 'id,name,mimeType,size'}, timeout=10)
        res.raise_for_status()
        return {'success': True, 'file': res.json()}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def stream_file(file_id, range_header=None):
    if not has_google_api():
        return None

    try:
        url = f'https://www.googleapis.com/drive/v3/files/{file_id}'
        params = {'alt': 'media', 'key': GOOGLE_API_KEY, 'acknowledgeAbuse': 'true'}
        headers = {'Range': range_header} if range_header else {}

        res = requests.get(url, params=params, headers=headers, stream=True, timeout=30)
        content_type = res.headers.get('Content-Type', '')

        # Nếu Google trả về HTML (cảnh báo virus / file lớn)
        if 'text/html' in content_type:
            print(f"⚠️ Google Drive trả về HTML. Đang trích xuất token...")
            
            # ⭐ Chỉ đọc 100KB đầu tiên để tránh tràn RAM
            html_chunks = []
            chunk_size = 0
            for chunk in res.iter_content(chunk_size=10240):
                html_chunks.append(chunk)
                chunk_size += len(chunk)
                if chunk_size > 100 * 1024:  # 100KB
                    break
            html_content = b"".join(html_chunks).decode('utf-8', errors='ignore')

            # Tìm form xác nhận của Google Drive
            match_action = re.search(r'action="([^"]+)"', html_content)
            match_uuid = re.search(r'name="uuid" value="([^"]+)"', html_content)
            match_confirm = re.search(r'name="confirm" value="([^"]+)"', html_content)

            if match_action and match_uuid and match_confirm:
                action_url = match_action.group(1).replace('&amp;', '&')
                uuid = match_uuid.group(1)
                confirm = match_confirm.group(1)

                # Dùng Session để giữ cookie
                s = requests.Session()
                bypass_params = {'id': file_id, 'export': 'download', 'confirm': confirm, 'uuid': uuid}
                
                res2 = s.get(action_url, params=bypass_params, headers=headers, stream=True, timeout=30)
                if res2.status_code in (200, 206):
                    print(f"✅ Bypass thành công!")
                    return res2
                else:
                    print(f"⚠️ Bypass thất bại: {res2.status_code}")
                    return None
            else:
                print(f"❌ Không tìm thấy form xác nhận. Google có thể đã chặn.")
                return None

        if res.status_code in (200, 206):
            return res
        else:
            print(f"⚠️ Google Drive trả về lỗi: {res.status_code}")
            return None
    except Exception as e:
        print(f'❌ Stream error: {e}')
        return None
