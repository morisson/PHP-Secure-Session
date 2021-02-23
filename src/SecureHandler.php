<?php
/**
 * Encrypt PHP session data for the internal PHP save handlers
 *
 * The encryption is built using libsodium extension 
 *
 * @author    Enrico Zimuel (enrico@zimuel.it)
 * @copyright MIT License
 */
namespace PHPSecureSession;

use SessionHandler;

class SecureHandler extends SessionHandler
{
    /**
     * Encryption and authentication key
     * @var string
     */
    protected $key;

    /**
     * Constructor
     */
    public function __construct()
    {
        if (! extension_loaded('sodium')) {
            throw new \RuntimeException(sprintf(
                "You need the Sodium extension to use %s",
                __CLASS__
            ));
        }
        if (! extension_loaded('mbstring')) {
            throw new \RuntimeException(sprintf(
                "You need the Multibytes extension to use %s",
                __CLASS__
            ));
        }
    }

    /**
     * Open the session
     *
     * @param string $save_path
     * @param string $session_name
     * @return bool
     */
    public function open($save_path, $session_name)
    {
        $this->key = $this->getKey('KEY_' . $session_name);
        return parent::open($save_path, $session_name);
    }

    /**
     * Read from session and decrypt
     *
     * @param string $id
     */
    public function read($id)
    {
        $data = parent::read($id);
        return empty($data) ? '' : $this->decrypt($data, $this->key);
    }

    /**
     * Encrypt the data and write into the session
     *
     * @param string $id
     * @param string $data
     */
    public function write($id, $data)
    {
        return parent::write($id, $this->encrypt($data, $this->key));
    }

    /**
     * Encrypt and authenticate
     *
     * @param string $data
     * @param string $key
     * @return string
     */
    protected function encrypt($data, $key)
    {


	$nonce = sodium_randombytes_buf( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($data, $nonce, $key);
        if ($ciphertext === false) {
             throw new \Exception('Unable to encrypt');
        }
        sodium_memzero($key);
        sodium_memzero($data);
	return $nonce.$ciphertext;
    }

    /**
     * Authenticate and decrypt
     *
     * @param string $data
     * @param string $key
     * @return string
     */
    protected function decrypt($data, $key)
    {

        $nonce = mb_substr($data,0,SODIUM_CRYPTO_SECRETBOX_NONCEBYTES,"8bit");
        $ciphertext = mb_substr($data,SODIUM_CRYPTO_SECRETBOX_NONCEBYTES,null,"8bit");

        $cleartext = sodium_crypto_secretbox_open($ciphertext,$nonce,$key);

        if ($cleartext === false) {
             throw new \Exception('Unable to decrypt');
        }
        sodium_memzero($key);
        return $cleartext;
    }

    /**
     * Get the encryption and authentication keys from cookie
     *
     * @param string $name
     * @return string
     */
    protected function getKey($name)
    {
        if (empty($_COOKIE[$name])) {
            $key = sodium_crypto_secretbox_keygen();
            $cookieParam = session_get_cookie_params();
            $encKey      = sodium_bin2base64($key,SODIUM_BASE64_VARIANT_URLSAFE);
            setcookie(
                $name,
                $encKey,
                // if session cookie lifetime > 0 then add to current time
                // otherwise leave it as zero, honoring zero's special meaning
                // expire at browser close.
                ($cookieParam['lifetime'] > 0) ? time() + $cookieParam['lifetime'] : 0,
                $cookieParam['path'],
                $cookieParam['domain'],
                $cookieParam['secure'],
                $cookieParam['httponly']
            );
            $_COOKIE[$name] = $encKey;
        } else {
            $key = sodium_base642bin($_COOKIE[$name],SODIUM_BASE64_VARIANT_URLSAFE);
            if ($key === false) {
                throw new \Exception('Can\'t retrieve key from cookie');
            }
        }
        return $key;
    }
}
