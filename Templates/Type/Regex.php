<?php

namespace Novutec\WhoisParser\Templates\Type;

use Novutec\WhoisParser\Result\Result;

abstract class Regex extends AbstractTemplate {

    protected $convertFromHtml = false;

    /**
     * @param Result $result
     * @param $rawdata
     */
    public function parse($result, $rawdata)
    {
        $this->parseRateLimit($rawdata);

        // check if there is a block to be cutted from HTML response
        if (isset($this->htmlBlock)) {
            preg_match($this->htmlBlock, $rawdata, $htmlMatches);

            if (isset($htmlMatches[0])) {
                $rawdata = preg_replace('/\s\s+/', "\n", $htmlMatches[0]);
            }
        }

        // lookup all blocks of template
        foreach ($this->blocks as $blockKey => $blockRegEx) {
            // try to match block regex against WHOIS rawdata
            if (!preg_match_all($blockRegEx, $rawdata, $blockMatches)) {
                continue;
            }

            // use matched block to lookup for blockItems
            foreach ($blockMatches[0] as $item) {
                foreach ($this->blockItems[$blockKey] as $itemRegEx => $target) {
                    // try to match blockItem regex against block
                    if (preg_match_all($itemRegEx, $item, $itemMatches)) {
                        // set matched items to Result
                        $value = end($itemMatches);
                        if ($this->convertFromHtml) {
                            if (is_array($value)) {
                                foreach($value as $k => $v) {
                                    $value[$k] = html_entity_decode(strip_tags($v));
                                }
                            } else {
                                $value = html_entity_decode(strip_tags($value));
                            }
                        }
                        $result->addItem($target, $value);
                    }
                }
            }
        }

        // if there are still contact handles after parsing then
        // these contacts are used for more types e.g. one handle for admin and
        // tech so we are going to clone this matching handles
        if (isset($result->network->contacts)) {
            // lookup all left over handles in network
            foreach ($result->network->contacts as $type => $handle) {
                if (! is_string($handle)) {
                    continue;
                }

                // lookup all contacts in Result
                foreach ($result->contacts as $contactType => $contactArray) {
                    foreach ($contactArray as $contactObject) {
                        // if contact handle in network matches the one in
                        // Result, we have to clone it
                        if (strtolower($contactObject->handle) !== strtolower($handle)) {
                            continue;
                        }

                        if (empty($result->contacts->$type)) {
                            $result->contacts->$type = Array();
                        }
                        array_push($result->contacts->$type, $contactObject);
                        unset($result->network->contacts->$type);
                        break 2;
                    }
                }
            }
        }

        // check availability upon type - IP addresses are always registered
        if (isset($this->available) && strlen($this->available)) {
            preg_match_all($this->available, $rawdata, $matches);

            $value = $matches[0];
            if ($this->convertFromHtml && (!is_array($value))) {
                $value = html_entity_decode(strip_tags($value));
            }
            $result->addItem('registered', empty($value));
        }
    }
}
