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
        $this->assertInstanceOf(\Novutec\DomainParser\Parser::class, $result);
        $this->assertTrue(true, 'true is true');
    }

    public function parseData(): array
    {
        return [
            [ 'google.com', true ]
        ];
    }

}
