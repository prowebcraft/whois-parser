<?php

use Novutec\WhoisParser\Parser;
use PHPUnit\Framework\TestCase;

class ParserTest extends TestCase
{

    /**
     * @dataProvider parseData
     * @return void
     */
    public function testParse(string $domain): void
    {
        $parser = new Parser();
        $result = $parser->lookup($domain);
        $this->assertInstanceOf(\Novutec\WhoisParser\Result\Result::class, $result);
        $this->assertTrue(true, 'true is true');
    }

    public static function parseData(): array
    {
        return [
            [ 'google.com', true ]
        ];
    }

}
