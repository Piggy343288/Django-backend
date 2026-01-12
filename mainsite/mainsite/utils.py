#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
图片处理工具函数
实现双线性插值缩放的图片压缩功能
"""

import os
from io import BytesIO
from PIL import Image, ImageOps
import tempfile


class ImageCompressor:
    """图片压缩器类，使用双线性插值进行缩放"""
    
    def __init__(self, max_size=(800, 600), quality=85):
        """
        初始化图片压缩器
        
        Args:
            max_size (tuple): 最大尺寸(width, height)
            quality (int): JPEG质量，1-100之间，默认为85
        """
        self.max_size = max_size
        self.quality = quality
    
    def bilinear_resize(self, image, new_width, new_height):
        """
        使用双线性插值缩放图片
        
        Args:
            image: PIL Image对象
            new_width (int): 新宽度
            new_height (int): 新高度
            
        Returns:
            PIL.Image: 缩放后的图片
        """
        # 使用PIL的LANCZOS重采样算法（近似双线性插值）
        return image.resize((new_width, new_height), Image.Resampling.LANCZOS)
    
    def calculate_new_size(self, original_width, original_height):
        """
        计算新的图片尺寸，保持宽高比
        
        Args:
            original_width (int): 原始宽度
            original_height (int): 原始高度
            
        Returns:
            tuple: (new_width, new_height)
        """
        max_width, max_height = self.max_size
        
        # 计算缩放比例
        ratio = min(max_width / original_width, max_height / original_height)
        
        # 如果图片已经小于最大尺寸，不需要缩放
        if ratio >= 1:
            return original_width, original_height
        
        # 计算新的尺寸
        new_width = int(original_width * ratio)
        new_height = int(original_height * ratio)
        
        return new_width, new_height
    
    def compress_image(self, image_data, output_format='JPEG'):
        """
        压缩图片
        
        Args:
            image_data (bytes): 图片数据
            output_format (str): 输出格式，默认为'JPEG'
            
        Returns:
            bytes: 压缩后的图片数据
        """
        try:
            # 从字节数据创建Image对象
            image = Image.open(BytesIO(image_data))
            
            # 自动调整方向（根据EXIF数据）
            image = ImageOps.exif_transpose(image)
            
            # 转换为RGB模式（如果需要）
            if image.mode in ('RGBA', 'P'):
                # 创建白色背景
                background = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'P':
                    image = image.convert('RGBA')
                background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else None)
                image = background
            elif image.mode != 'RGB':
                image = image.convert('RGB')
            
            original_width, original_height = image.size
            
            # 计算新的尺寸
            new_width, new_height = self.calculate_new_size(original_width, original_height)
            
            # 如果尺寸有变化，进行缩放
            if new_width != original_width or new_height != original_height:
                image = self.bilinear_resize(image, new_width, new_height)
            
            # 保存到内存缓冲区
            output_buffer = BytesIO()
            
            # 根据输出格式保存图片
            if output_format.upper() == 'JPEG':
                image.save(output_buffer, format='JPEG', quality=self.quality, optimize=True)
            elif output_format.upper() == 'PNG':
                image.save(output_buffer, format='PNG', optimize=True)
            elif output_format.upper() == 'WEBP':
                image.save(output_buffer, format='WEBP', quality=self.quality, optimize=True)
            else:
                # 默认为JPEG
                image.save(output_buffer, format='JPEG', quality=self.quality, optimize=True)
            
            return output_buffer.getvalue()
            
        except Exception as e:
            raise Exception(f"图片压缩失败: {str(e)}")
    
    def compress_image_from_file(self, file_path, output_format='JPEG'):
        """
        从文件压缩图片
        
        Args:
            file_path (str): 图片文件路径
            output_format (str): 输出格式
            
        Returns:
            bytes: 压缩后的图片数据
        """
        try:
            with open(file_path, 'rb') as f:
                image_data = f.read()
            return self.compress_image(image_data, output_format)
        except Exception as e:
            raise Exception(f"读取文件失败: {str(e)}")
    
    def compress_image_from_upload(self, uploaded_file, output_format='JPEG'):
        """
        从Django UploadedFile对象压缩图片
        
        Args:
            uploaded_file: Django的UploadFile对象
            output_format (str): 输出格式
            
        Returns:
            bytes: 压缩后的图片数据
        """
        try:
            # 读取上传的文件数据
            image_data = uploaded_file.read()
            return self.compress_image(image_data, output_format)
        except Exception as e:
            raise Exception(f"处理上传文件失败: {str(e)}")
    
    def save_compressed_image(self, compressed_data, save_path):
        """
        保存压缩后的图片到文件
        
        Args:
            compressed_data (bytes): 压缩后的图片数据
            save_path (str): 保存路径
        """
        try:
            with open(save_path, 'wb') as f:
                f.write(compressed_data)
        except Exception as e:
            raise Exception(f"保存图片失败: {str(e)}")


def compress_user_head_image(uploaded_file, user_id, max_size=(300, 300), quality=85):
    """
    压缩用户头像图片的便捷函数
    
    Args:
        uploaded_file: Django UploadedFile对象
        user_id (int): 用户ID
        max_size (tuple): 最大尺寸
        quality (int): JPEG质量
        
    Returns:
        str: 临时文件路径
    """
    compressor = ImageCompressor(max_size=max_size, quality=quality)
    
    try:
        # 压缩图片
        compressed_data = compressor.compress_image_from_upload(uploaded_file)
        
        # 创建临时文件，使用NamedTemporaryFile确保正确的文件处理
        temp_file = tempfile.NamedTemporaryFile(suffix='.jpg', prefix=f'user_{user_id}_compressed_', delete=False)
        temp_path = temp_file.name
        temp_file.close()  # 关闭文件句柄以避免锁定
        
        # 保存压缩后的图片
        compressor.save_compressed_image(compressed_data, temp_path)
        
        return temp_path
        
    except Exception as e:
        # 如果出错，尝试删除临时文件
        try:
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.unlink(temp_path)
        except:
            pass
        raise Exception(f"压缩用户头像失败: {str(e)}")


def get_image_info(image_data):
    """
    获取图片信息
    
    Args:
        image_data (bytes): 图片数据
        
    Returns:
        dict: 图片信息
    """
    try:
        image = Image.open(BytesIO(image_data))
        return {
            'format': image.format,
            'mode': image.mode,
            'size': image.size,
            'width': image.width,
            'height': image.height,
            'has_transparency': image.mode in ('RGBA', 'LA') or 'transparency' in image.info
        }
    except Exception as e:
        return {'error': str(e)}


def is_image_file(filename):
    """
    检查文件是否为图片
    
    Args:
        filename (str): 文件名
        
    Returns:
        bool: 是否为图片文件
    """
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.ico'}
    return os.path.splitext(filename.lower())[1] in image_extensions


def validate_image_size(image_data, max_file_size_mb=10):
    """
    验证图片文件大小
    
    Args:
        image_data (bytes): 图片数据
        max_file_size_mb (float): 最大文件大小（MB）
        
    Returns:
        bool: 文件大小是否合法
    """
    file_size_mb = len(image_data) / (1024 * 1024)
    return file_size_mb <= max_file_size_mb


# 默认压缩器实例
default_compressor = ImageCompressor(max_size=(800, 600), quality=85)