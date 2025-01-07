from django.db import models

GENDER_CHOICE = {
    'MALE': 'male',
    'FEMALE': 'female'
}

# Model for Blocked jwt token
class BlockedToken(models.Model):
    user = models.ForeignKey(
        'AppUser',  # Reference to the AppUser model
        on_delete=models.CASCADE,  # Delete tokens if the user is deleted
        related_name='blocked_tokens'  # Name for reverse relationship
    )
    value = models.TextField()
    expire_time = models.DateTimeField()
    def __str__(self):
        return self.value


# Model for AppUser
class AppUser(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100, unique=True)
    password = models.CharField(max_length=100)
    age = models.IntegerField(default=0)
    gender = models.CharField(
        max_length=6,
        choices=GENDER_CHOICE,
        default='MALE'
    )
    profileImg = models.ImageField(upload_to='user_profile_img/', null=True, blank=True)
    def __str__(self):
        return self.name
