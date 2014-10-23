<?php
//Konfiguration zur Anzeige von Fehlern
//Auf http://www.php.net/manual/de/function.error-reporting.php sind die verfügbaren Modi aufgelistet

//Seit php-5.3 ist eine Angabe der TimeZone Pflicht
if (version_compare(phpversion(), '5.3') != -1) {
	if (E_ALL > E_DEPRECATED) {
		@error_reporting(E_ALL ^ E_NOTICE ^ E_DEPRECATED);
	} else {
		@error_reporting(E_ALL ^ E_NOTICE);
	}
	date_default_timezone_set('Europe/Berlin');
} else {
	@error_reporting(E_ALL ^ E_NOTICE);
}
@ini_set('display_errors','On');

clearstatcache(); //cache leeren
?>
<html>
<!--Copyright by FeTTsack-->
<head>
<title>PSW-Converter</title>
</head>
<body>
<?php
$control = 0;
if(empty($_POST)==false){
	if(isset($_POST['submitzufall'])){
		$zufallszahl = rand(5, 10);
		$psw = substr(str_shuffle("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVW!§$%&/()=?@#"), 0, $zufallszahl);
	}else{
		$psw = $_POST['pswtext'];
	}
	
	if(isset($_POST['saltfest'])){
		//übergabe der manuel eingetragenen Salts
		$saltdes = $_POST['tsaltdes'];
		$saltdesext = $_POST['tsaltdesext'];
		$saltmd5 = $_POST['tsaltmd5'];	
		$saltapr1 = $_POST['tsaltapr1'];
		$saltapr1 = substr($saltapr1, 6, 8);
		$saltblowf = $_POST['tsaltblowf'];
		$saltsha256 = $_POST['tsaltsha256'];
		$saltsha512 = $_POST['tsaltsha512'];
	}else{
		//generiert für alle salt verschiedene Zufallszahlen.
		$saltdes = substr(str_shuffle("abcdefghijklmnopqrstuvwxyz0123456789"), 0, 2);
		$saltdesext = '_'.substr(str_shuffle(".abcdefghijklmnopqrstuvwxyz0123456789"), 0, 8);
		$saltmd5 = '$1$'.substr(str_shuffle("./abcdefghijklmnopqrstuvwxyz0123456789"), 0, 8).'$';	
		$saltapr1 = substr(str_shuffle("./abcdefghijklmnopqrstuvwxyz0123456789"), 0, 8);
		$saltblowf = '$2a$07$'.substr(str_shuffle("./abcdefghijklmnopqrstuvwxyz0123456789"), 0, 20).'$';
		$saltsha256 = '$5$'.substr(str_shuffle("./abcdefghijklmnopqrstuvwxyz0123456789"), 0, 16).'$';
		$saltsha512 = '$6$'.substr(str_shuffle("./abcdefghijklmnopqrstuvwxyz0123456789"), 0, 16).'$';
	}
	
	if(isset($_POST['hashfest'])){
		$pswhash = hash($_POST['thash'], $psw);
	}else{
		$pswhash = $psw;
	}
	//hashen und crypten des passworts
	$pswsha1 = sha1($psw);
	$pswmd5 = MD5($psw);
	$pswcryptdes = crypt($psw, $saltdes);
	$pswcryptextdes = crypt($psw, $saltdesext);
	$pswcryptmd5 = crypt($psw, $saltmd5);
	$pswcryptblowf = crypt($psw, $saltblowf);
	$pswcryptsha256 = crypt($psw, $saltsha256);
	$pswcryptsha512 = crypt($psw, $saltsha512);

    //Anfang apr1 verschlüsseln 
    $len = strlen($psw);  
    $text = $psw.'$apr1$'.$saltapr1;  
    $bin = pack("H32", md5($psw.$saltapr1.$psw));  
    for($i = $len; $i > 0; $i -= 16) { $text .= substr($bin, 0, min(16, $i)); }  
    for($i = $len; $i > 0; $i >>= 1) { $text .= ($i & 1) ? chr(0) : $psw{0}; }  
    $bin = pack("H32", md5($text));  
    for($i = 0; $i < 1000; $i++) {  
        $new = ($i & 1) ? $psw : $bin;  
        if ($i % 3) $new .= $saltapr1;  
        if ($i % 7) $new .= $psw;  
        $new .= ($i & 1) ? $bin : $psw;  
        $bin = pack("H32", md5($new));  
    }  
    for ($i = 0; $i < 5; $i++) {  
        $k = $i + 6;  
        $j = $i + 12;  
        if ($j == 16) $j = 5;  
        $tmp = $bin[$i].$bin[$k].$bin[$j].$tmp;  
    }  
    $tmp = chr(0).chr(0).$bin[11].$tmp;  
    $tmp = strtr(strrev(substr(base64_encode($tmp), 2)),  
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",  
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");  
    $pswcryptapr1md5 = '$apr1$'.$saltapr1."$".$tmp;  
	//end apr1 verschlüsseln
	

?>
	<table border="1">
	<tr>
		<th>VerschlüsselungsArt</th>
		<th>Passwort</th>
		<th>Salt</th>
	</tr>
	<tr>
		<td>crypt(DES)</td>
		<td><b><?php echo $pswcryptdes; ?></b></td>
		<td><?php echo $saltdes; ?></td>
	</tr>
	<tr>
		<td>crypt(DES) ext</td>
		<td><b><?php echo $pswcryptextdes; ?></b></td>
		<td><?php echo $saltdesext; ?></td>
	</tr>
	<tr>
		<td>crypt(MD5)</td>
		<td><b><?php echo $pswcryptmd5; ?></b></td>
		<td><?php echo $saltmd5; ?></td>
	</tr>
	<tr>
		<td>crypt(apr1-MD5)</td>
		<td><b><?php echo $pswcryptapr1md5; ?></b></td>
		<td><?php echo '$apr1$'.$saltapr1.'$'; ?></td>
	</tr>
	<tr>
		<td>crypt(Blowfish)</td>
		<td><b><?php echo $pswcryptblowf; ?></b></td>
		<td><?php echo $saltblowf; ?></td>
	</tr>
	<tr>
		<td>crypt(SHA-256)</td>
		<td><b><?php echo $pswcryptsha256; ?></b></td>
		<td><?php echo $saltsha256; ?></td>
	</tr>
	<tr>
		<td>crypt(SHA-512)</td>
		<td><b><?php echo $pswcryptsha512; ?></b></td>
		<td><?php echo $saltsha512; ?></td>
	</tr>
	<tr>
		<td>sha-1</td>
		<td><b><?php echo $pswsha1; ?></b></td>
	</tr>
	<tr>
		<td>md5</td>
		<td><b><?php echo $pswmd5; ?></b></td>
	</tr>
	<tr>
		<td><?php if(isset($_POST['hashfest'])){ echo $_POST['thash']; }else{ echo "kein Hash"; } ?></td>
		<td><b><?php echo $pswhash; ?></b></td>
	</tr>
	</table>
	<?php
}
?>

<table>
<form method="post" action="?" name="form">
	<tr>
	<td>Passwort:</td>
	<td><input type="text" name="pswtext" value="<?php echo $psw; ?>"/></td>
	<td><input type="submit" name="submitpsw" value="Generieren"/></td>
	<td><input type="submit" name="submitzufall" value="ZufallsPSW Generieren"/></td>
	</tr>
	<tr><td>&nbsp;</td></tr>
	<tr>
	<td><input type="checkbox" name="saltfest" onclick="alert('lege die Salt fest welche für die Berechnung benutzt wird')" value="salt" <?php if(isset($_POST['saltfest'])){ echo "checked"; } ?>>keine Zufalls-Salt verwenden</input></td>
	<td></td><td></td>
	<td><input type="checkbox" name="hashfest" onclick="alert('lege deine Hash fest welchen du magst')" value="hash" <?php if(isset($_POST['hashfest'])){ echo "checked"; } ?>>einen eigenen Hash festlegen</input></td>
	</tr>
	<tr>
	<td>DES-Salt</td><td><input type="text" name="tsaltdes" value="<?php if(isset($_POST['saltfest'])){ echo $saltdes; }else{ echo "12"; } ?>"/></td>
	<td></td>
	<td>eigene Hash <input type="text" name="thash" value="<?php if(isset($_POST['hashfest'])){ echo $_POST['thash']; }else{ echo "crc32"; } ?>"/></td>
	</tr>
	<tr>
	<td>DES-ext-Salt</td><td><input type="text" name="tsaltdesext" value="<?php if(isset($_POST['saltfest'])){ echo $saltdesext; }else{ echo "_12345678"; } ?>"/></td>
	</tr>
	<tr>
	<td>MD5-Salt</td><td><input type="text" name="tsaltmd5" value="<?php if(isset($_POST['saltfest'])){ echo $saltmd5; }else{ echo "$1$12345678$"; } ?>"/></td>
	</tr>
	<tr>
	<td>apr1-Salt</td><td><input type="text" name="tsaltapr1" value="<?php if(isset($_POST['saltfest'])){ echo '$apr1$'.$saltapr1.'$'; }else{ echo '$apr1$12345678$'; } ?>"/></td>
	</tr>
	<tr>
	<td>Blowfish-Salt</td><td><input type="text" name="tsaltblowf" value="<?php if(isset($_POST['saltfest'])){ echo $saltblowf; }else{ echo "$2a$07$12345678901234567890$"; } ?>"/></td>
	</tr>
	<tr>
	<td>SHA256-Salt</td><td><input type="text" name="tsaltsha256" value="<?php if(isset($_POST['saltfest'])){ echo $saltsha256; }else{ echo "$5$1234567890123456$"; } ?>"/></td>
	</tr>
	<tr>
	<td>SHA512-Salt</td><td><input type="text" name="tsaltsha512" value="<?php if(isset($_POST['saltfest'])){ echo $saltsha512; }else{ echo "$6$1234567890123456$"; } ?>"/></td>
	</tr>
</form>
</table>

</body>
</html>
	<center>
	<div id="footer">
		&copy; <a href="http://fettsack.de.vc"	title="Startseite">FeTTsack</a> &middot; 2012 &middot; <a href="http://impressum/" title="Impressum">Impressum</a>
	</div>
	</center>

