<?php
/**
 * Novutec Domain Tools
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category   Novutec
 * @package    DomainParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser\Templates\Type
 */
namespace Novutec\WhoisParser\Templates\Type;

use Novutec\WhoisParser\Exception\RateLimitException;
use Novutec\WhoisParser\Result\Result;

/**
 * WhoisParser AbstractTemplate
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
abstract class AbstractTemplate
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected $blocks = array();

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array();

    /**
     * Writing data to properties
     *
     * @param  string $name
     * @param  mixed $value
     * @return void
     */
    public function __set($name, $value)
    {
        $this->{$name} = $value;
    }

    /**
     * Checking data
     *
     * @param  mixed $name
     * @return boolean
     */
    public function __isset($name)
    {
        return isset($this->{$name});
    }

    /**
     * Reading data from properties
     *
     * @param  string $name
     * @return void
     */
    public function __get($name)
    {
        if (isset($this->{$name})) {
            return $this->{$name};
        }
        
        return null;
    }

    /**
     * Load Template
     * 
     * Returns a template object, if not null.
     *
     * @param  string $template
     * @return mixed
     */
    public static function factory($template, $customNamespace = null)
    {
        $template = ucfirst(str_replace('.', '_', $template));

        $obj = null;

        // Ensure the custom namespace ends with a
        if ($customNamespace) {
            $customNamespace = rtrim($customNamespace, '\\') .'\\';
        }
        if ($customNamespace && (strpos($template, '\\') !== false) && class_exists($template, $customNamespace)) {
            $class = $template;
            $obj = new $class();
        } elseif ($customNamespace && (strlen($customNamespace) > 1) && class_exists($customNamespace . $template)) {
            $class = $customNamespace . $template;
            $obj = new $class();
        } elseif (class_exists('Novutec\WhoisParser\Templates\\'. $template)) {
            $class = 'Novutec\WhoisParser\Templates\\'. $template;
            $obj = new $class();
        }
        return $obj;
    }

    /**
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {}


    /**
     * @param Result $result
     * @param $rawdata
     * @throws RateLimitException
     */
    public abstract function parse($result, $rawdata);


    protected function parseRateLimit($rawdata)
    {
        if (isset ($this->rateLimit) && strlen($this->rateLimit)) {
            $count = preg_match_all($this->rateLimit, $rawdata, $matches);
            if ($count > 0) {
                throw new RateLimitException("Rate limit exceeded for server");
            }
        }
    }


    /**
     * Perform any necessary translation on the raw data before processing (for example, re-encoding to UTF-8)
     *
     * @param string $rawdata
     * @param array $config
     * @return string
     */
    public function translateRawData($rawdata, $config)
    {
        if (array_key_exists('encoding', $config)) {
            switch (strtolower($config['encoding'])) {
                case 'iso-8859-1':
                    $rawdata = utf8_encode($rawdata);
                    break;
            }
        }

        return $rawdata;
    }
}