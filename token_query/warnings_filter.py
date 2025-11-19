"""
过滤 urllib3 和其他库的警告信息
"""
import warnings

def suppress_warnings():
    """抑制常见的警告信息"""
    # 抑制 urllib3 的 OpenSSL 警告
    warnings.filterwarnings('ignore', message='urllib3 v2 only supports OpenSSL')
    # 抑制其他 NotOpenSSLWarning
    warnings.filterwarnings('ignore', category=DeprecationWarning)

