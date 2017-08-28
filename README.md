<h1>Duxe</h1>
<img src="duxe.png">
<p><b>Duxe</b> is an information gathering tool. it can discover subdomains with online open tool no need to brutforce for the firste time of gathering information, search with shodan, make nmap test, get what CMS is using.</p><br>
<h2>Requirement:</h2>
<p>
<ul>
<li><a href="https://shodan.readthedocs.io/en/latest/index.html">Shodan</a>: you can install it <code>pip install shodan</code></li>
<li>requests==2.12.4</li>
<li>beautifulsoup4==4.6.0</li>
<li>shodan==1.7.4</li>
<li>SocksiPy_branch==1.01</li>
</ul>
<h3>OR:</h3>
you can do <code>pip install -r requirements.txt</code></p>
<h2>Usage:</h2>
<code>python duxe.py [-h] -host HOST [-nmap] [-robot] [-log] [-tor]
  -h, --help  show this help message and exit
  -host HOST  The target to test exemple: 'exemple.com'
  -nmap       Make a Nmap test
  -log        Log the output to a file
  -tor        Use tor to make the request
  -version    Print version and exit</code>
<h3>Exemple: pythont duxe.py -host exemple.com -tor -log</h3>
<a href="https://hihebark.wordpress.com/2017/08/26/made-a-domain-information-gathering-tool/">more about the tool</a>
