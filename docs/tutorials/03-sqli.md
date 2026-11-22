# Corriger une SQL Injection

## Vulnerable (PHP)
$sql = "SELECT * FROM users WHERE login='" . $_POST['login'] . "'";

## Corrige (PDO)
$stmt = $pdo->prepare("SELECT * FROM users WHERE login = ?");
$stmt->execute([$_POST['login']]);

## Corrige (Python)
cursor.execute("SELECT * FROM users WHERE login = %s", (login,))

## References
- OWASP : https://owasp.org/www-community/attacks/SQL_Injection
