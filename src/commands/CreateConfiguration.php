<?php


namespace Kangst\JWTAuth\commands;


use think\console\Command;

class CreateConfiguration extends Command
{
    protected function configure()
    {
        $this->setName('jwt:generate_config')->setDescription('生成');
    }
}