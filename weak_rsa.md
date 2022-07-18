# Weak RSA
## RSA decryption via public key
``````

cd /opt
git clone https://github.com/Ganapati/RsaCtfTool.git
sudo apt-get install libgmp3-dev libmpc-dev
cd RsaCtfTool
cp ~/htb/Beginner_Track/Weak_RSA/key.pub ~/htb/Beginner_Track/Weak_RSA/flag.enc .
sudo apt install python3-venv  
python3 -m venv .venv  
source .venv/bin/activate  
python3 -m pip install gmpy2  
Then remove gmpy2 from your local requirements.txt file  
pip3 install -r "requirements.txt"  

Run:

./RsaCtfTool.py --publickey ./key.pub --uncipherfile ./flag.enc

Response:

HTB{flag}

``````

![image](https://m0d1cumc0rvu5.github.io/docs/assets/images/20220625005045.png)

#hacking
