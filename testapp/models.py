from django.db import models


# Create your models here.
class Payload(models.Model):
    content = models.TextField()
