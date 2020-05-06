# THINK JWT
thinkphp json web token package, By unofficial.

## 使用扩展包
- **composer request kangst/think-jwt**
- **加载命令文件到服务并执行命令创建jwt.php配置文件**
~~~
PATH:
application/command.php

CODE:
return [
    \Kangst\JWTAuth\Console\GenerateConfigFile::class,
];

return [
    'command alias' => \Kangst\JWTAuth\Console\GenerateConfigFile::class,
];

RUN COMMAND:
php think jwt:generate_jwt
~~~
- **jwt使用**
~~~
namespace app\api\controller\v1;


use app\api\controller\Base;
use Kangst\JWTAuth\JWTAuth;

class User extends Base
{
    /**
     * @var JWTAuth
     */
    protected $auth;

    public function __construct($app = null, JWTAuth $auth)
    {
        parent::__construct($app);
        $this->auth = $auth;
    }

    public function login()
    {
        $credentials = $this->request->only(['name', 'email']);
        $token = $this->auth->attempt($credentials);
        $user = $this->auth->setToken($token)->user();
        $resh_token = $this->auth->setToken($token)->refresh();

        $data = array(
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $this->auth->factory()->getTTL() * 60,
            'user' => $user->user()->toArray(),
            'resh_token' => $resh_token,
        );
        $this->result($data, 0, 'success', 'JSON');
    }
}
~~~

## 还在完善中，请多多Fork
项目地址：[github](https://github.com/admininfon/think-jwt)<br> 
URL:https://github.com/admininfon/think-jwt