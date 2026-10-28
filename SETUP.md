# Guardian - Setup (about 3 minutes)

Thanks for testing Guardian! It is a free Chrome extension that watches for
scam websites and scam emails and shows a clear warning. Everything runs on
your own computer; nothing about your browsing is ever sent anywhere.

## Install

1. Unzip this folder somewhere you will remember (for example, your Desktop).
   Keep all the files together in one folder.
2. Open Google Chrome.
3. In the address bar, type this and press Enter:

       chrome://extensions

4. Turn ON the switch in the top-right corner that says **Developer mode**.
5. Click the **Load unpacked** button (top-left).
6. Choose the Guardian folder you unzipped in step 1, then click Select.

Guardian is now installed. You will see a small shield icon near the top-right
of Chrome. Click it any time to see how many scams it has blocked, or to
check a page you are unsure about.

### One extra step to try the practice pages

To open the safe practice pages below, Guardian needs permission to see local
files:

1. Go back to `chrome://extensions`.
2. Find Guardian and click **Details**.
3. Turn ON **Allow access to file URLs**.

## Try it (all completely safe, nothing real)

Open these files from the `test-pages` folder by dragging them into Chrome:

- `fake-virus-alert.html` - a fake "your computer is infected, call this
  number" page. Guardian should cover it with a red warning.
- `fake-google-login.html` - a fake Google sign-in page.
- `fake-bitb-login.html` - a fake recruiter page; wait about 6 seconds and a
  fake sign-in popup appears, and Guardian catches it.
- `reported-scam-site.html` - a page caught because its address is on a scam
  blacklist.

Then browse a few normal sites you trust (your bank, Amazon, the news).
Nothing should happen. Guardian is designed to stay quiet unless there is a
real problem.

Want a quick guided tour instead? Open `demo/guardian-demo.html` and press
Play.

## What to tell Olivia after testing

- Did any warning pop up on a normal, safe website? (It should not.)
- Were the warnings easy to read and understand?
- Did anything look broken or confusing?
- Anything you wish it did?

## Uninstall

Go to `chrome://extensions`, find Guardian, and click **Remove**. That is it.
