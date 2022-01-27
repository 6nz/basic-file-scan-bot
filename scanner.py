import discord
from discord import Embed, Emoji
from discord import emoji
import shutil
from discord.ext import commands, tasks
import os
import time
from datetime import date
from discord.utils import get
import io
import sys
from itertools import cycle
from discord.ext.commands.bot import Bot
from asyncio.tasks import wait
import asyncio
import json
import requests
import zipfile
os.system("clear")
from discord.ext.tasks import loop
import string
import random
import datetime
import hashlib
from discord.ext import (
  commands,
  tasks,
  )


from datetime import datetime
import requests, time, json
os.system("clear")


prefix = "."

client = discord.Client()
intents = discord.Intents.all()
client = commands.AutoShardedBot(
    description="Rev-9 Scanner",
    command_prefix=prefix,
    self_bot=False,
    guild_subscriptions=True, 
    intents=intents,
    shard_count=1
)
client.remove_command('help')

@client.event
async def on_message(message):
  await client.process_commands(message)

@client.event
async def on_message_edit(before, after):
    await client.process_commands(after)


@client.command(pass_context=True)
async def purge(ctx, limit: int):
  await ctx.channel.purge(limit=limit)
  await ctx.message.delete()

@client.command()
async def scan(ctx):
  await ctx.send('Please upload your file!')
  def check(message):
    attachments = message.attachments
    if len(attachments) == 0:
      return False
    attachment = attachments[0]
    return attachment.filename.endswith(('.exe', '.exe'))

  msg = await client.wait_for('message', check=check)
  file = msg.attachments[0]
  if file.filename == "main.py":
    await ctx.send("Please rename the file to something else...[don't use main.py]")
  else:
    await file.save(file.filename)
    time.sleep(1)
    shutil.move(f"{file.filename}", "files")
    print(f"DEBUG: Checking {file.filename}...")
    await ctx.send(f"Scanning {file.filename}... This might take a few mins... (120Sec)")
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': 'keyhere'}
    files = {'file': (f'files/{file.filename}', open(f'files/{file.filename}', 'rb'))}
    response = requests.post(url, files=files, params=params)
    dataxd = json.loads(response.content)  
    asd = dataxd['sha256']
    time.sleep(120)
    print(f"Hash: {asd}")
    url2 = 'https://www.virustotal.com/vtapi/v2/file/report'
    params2 = {'apikey': 'keyhere', 'resource': f'{asd}'}
    response2 = requests.get(url2, params=params2)
    data2 = json.loads(response2.content)  
    print(data2)
    print(data2['scan_id'])
    mid = data2['md5']
    total = data2['total']
    positives = data2['positives']
    sdate = data2['scan_date']
    scanid = data2['scan_id']
    avast = data2['scans']['Avast']['detected']
    mcafee = data2['scans']['McAfee']['detected']
    kasper = data2['scans']['Kaspersky']['detected']
    tach = data2['scans']['TACHYON']['detected']
    yandex = data2['scans']['Yandex']['detected']
    micro = data2['scans']['Microsoft']['detected']
    malware = data2['scans']['Malwarebytes']['detected']
    avastr = data2['scans']['Avast']['detected']['result']
    mcafeer = data2['scans']['McAfee']['detected']['result']
    kasperr = data2['scans']['Kaspersky']['detected']['result']
    tachr = data2['scans']['TACHYON']['detected']['result']
    yandexr = data2['scans']['Yandex']['detected']['result']
    micror = data2['scans']['Microsoft']['detected']['result']
    malwarer = data2['scans']['Malwarebytes']['detected']['result']
    os.system('cls')
    time.sleep(1)
    results = f"""```yaml
--------Credits-------- 
    
Scanned with: Rev-9 scanner
Made by: Marci
    
-----------------------
 
--------Info--------  
    
Sha256: {asd}
MD5: {mid}
Total: {total}
Positives: {positives}
Scan_date: {sdate}
Scan_id: {scanid}

-------------------- 
    
--------Scans--------
    
Avast: Detected - {avast}
McAfee: Detected - {mcafee}
Kaspersky: Detected - {kasper}
TACHYON: Detected - {tach}
Yandex: Detected - {yandex}
Microsoft: Detected - {micro}
Malwarebytes: Detected - {malware}
    
---------------------
```"""
    await ctx.send(results)
    os.remove(f'files/{file.filename}')
            
        
def Clear():
  os.system('clear')


@client.command()
async def cls(ctx):
  await ctx.message.delete()
  Clear()



@client.event
async def on_command_error(ctx, error): # b'\xfc
  error_str = str(error)
  error = getattr(error, 'original', error)
  if isinstance(error, commands.CommandNotFound):
    return
  elif isinstance(error, commands.CheckFailure):
    print(f"[ERROR]: You're missing permission to execute this command")           
  else:
    print(f"[ERROR]: {error_str}")

@client.event
async def on_ready():
    await client.change_presence(activity=discord.Streaming(name="Rev-9 Scanner", url="https://www.youtube.com/watch?v=P9zhLuKOqT8"))
    print("Bot is ready!")

client.run("token xd")