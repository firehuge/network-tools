# How to collect your GlobalProtect logs

Your IT team needs a log file from the GlobalProtect VPN app to see why the VPN is not working. It takes about one minute.

> Tip: If you can, try to connect once more right before you collect the logs. That way the problem is included in the file.

## Windows
1. Find the **GlobalProtect icon** (a globe) near the clock, at the bottom right of the screen. If you don't see it, click the small **^** arrow to show hidden icons.
2. Click the icon to open GlobalProtect.
3. Click the **menu button** in the top right corner of the GlobalProtect window. Depending on the version, it looks like a gear ⚙ or three lines ☰. Then click **Settings**.
4. In the window that opens, click the **Troubleshooting** tab.
5. Click **Collect Logs**. Wait until it says the logs were collected. This can take a minute.
6. Click **Open Folder**. A folder opens that contains a file named **GlobalProtectLogs.zip**.
7. Send that file to your engineer (see "How to send the file" below).

## Mac
1. Click the **GlobalProtect icon** (a globe) in the menu bar at the top right of the screen.
2. Click the **menu button** (gear ⚙ or three lines ☰) and choose **Settings**.
3. Click the **Troubleshooting** tab.
4. Click **Collect Logs** and wait for it to finish.
5. Click **Open Folder**. Look for **GlobalProtectLogs.tgz**, which is usually saved in your home folder.
6. Send that file to your engineer.

If the app won't open, you can collect the logs from Terminal instead:
```
sh /Applications/GlobalProtect.app/Contents/Resources/gp_support.sh /Users/$USER
```
The file is saved as `/Users/<your name>/GlobalProtectLogs.tgz`.

## Linux
**With the app window:** open GlobalProtect, click the menu (☰), then click **Settings**, then **Troubleshooting**, then **Collect Logs**, then **Open Folder**. Send **GlobalProtectLogs.tgz**.

**From the command line:**
```
globalprotect collect-log
```
The command prints where it saved the file. This is usually `~/.GlobalProtect/Collect.tgz`, but some versions save `~/.GlobalProtect/GlobalProtectLogs.tgz` instead.

## How to send the file
- Attach the file to your **help desk ticket**. This is the best option.
- Or email it to your engineer, if your company allows attachments of this size. The file can be 5 to 50 MB.
- If it's too big to email, put it in your company's shared drive (OneDrive, SharePoint, Google Drive) and send the link to your engineer.
- **Don't** rename the file or unzip it first, and don't post it in public places. It contains your username and computer details.

The file does not contain your password.

*Steps based on the Palo Alto Networks knowledge base article "How to Collect Logs from GlobalProtect App" and the GlobalProtect 6.2 user guide. Menu icons vary slightly between GlobalProtect 6.x versions.*
