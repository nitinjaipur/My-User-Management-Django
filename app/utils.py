import base64
import os

def load_env_file(env_file_path):
    """
    Loads environment variables from a .env file into the OS environment.

    :param env_file_path: The path to the .env file
    """
    with open(env_file_path) as f:
        for line in f:
            # Ignore empty lines and comments (lines starting with '#')
            line = line.strip()
            if line and not line.startswith('#'):
                # Split the line into key and value, and set the environment variable
                key, value = line.split('=', 1)
                os.environ[key] = value


IMG_TYPE = {
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'bmp': 'image/bmp',
    'tiff': 'image/tiff',
    'svg': 'image/svg+xml',
    'webp': 'image/webp',
}

def fetch_user_details(user):
    user_details = {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'age': user.age,
        'gender': user.gender
    }

    if user.profileImg:
        # Getting image type from image path
        profileImgType = (user.profileImg.path).split('.')[-1]
        # Getting mime type from image type
        mime_type = IMG_TYPE.get(profileImgType)
        image_path = user.profileImg.path
        with open(image_path, 'rb') as img_file:
            # Encode the image to base64
            image_data = base64.b64encode(img_file.read()).decode('utf-8')
            # Add the image data to the user data dictionary
            user_details['image_data'] = f"data:{mime_type};base64,{image_data}"
    
    return user_details