<?php
require_once 'includes/connect-db.php';
require_once 'includes/token.php';
session_start();

global $pdo;

if (isset($_SESSION['auth_token'])) {
    $payload = decryptToken($_SESSION['auth_token']);
    if ($payload && isset($payload['user_type'])) {
        $usertype = $payload['user_type'];

        if ($usertype == 0) {
            header('location: ./user');
        } elseif ($usertype == 1) {
            header('location: ./admin');
        }
    }
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    $stmt = $pdo->prepare('SELECT * FROM user WHERE email = ?');
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (is_array($user) && isset($user['password'])) {
        $password_is_verified = password_verify($password, $user['password']);
    } else {
        $password_is_verified = false;
    }

    if ($user && $password_is_verified) {
        // Create payload with user info
        $payload = [
            'user_id' => $user['iduser'],
            'user_email' => $user['email'],
            'user_type' => $user['usertype'],
            'user_name' => $user['f_name'],
            'iat' => time(),              // Issued At
        ];

        // Generate encrypted token
        $token = encryptToken($payload);

        // Store token in a session or secure cookie
        $_SESSION['auth_token'] = $token;

        // Alternatively, use an HttpOnly cookie for better security
        setcookie('auth_token', $token, [
            'expires' => time() + (30 * 24 * 60 * 60),
            'path' => '/',
            'httponly' => true,
            'secure' => true,
            'samesite' => 'Strict'
        ]);

        if ($user['usertype'] == 0) {
            header("Location: ./user");
            exit();
        } else {
            header("Location: ./admin");
            exit();
        }
    }
    // header("Location: " . $_SERVER['PHP_SELF']);
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <?php include_once './includes/favicon.php'; ?>
    <link href="css/styles.css" rel="stylesheet" />
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <title>MoneyMo - MoneyMo - Login</title>
</head>

<body class="bg-white">
    <main class="flex min-h-screen w-full max-w-screen">
        <!-- Left side: Login form -->
        <div class="flex flex-col relative justify-center w-full px-8 py-12 lg:px-24">
            <a href="" class="absolute top-0 left-0 flex justify-center items-center gap-2 px-6 py-4">
                <img src="assets/logo-circle.png"
                    alt="MoneyMo Logo" class="max-h-16 w-auto">
                <span class="text-3xl font-bold">MoneyMo</span>
            </a>

            <div class="flex flex-col justify-center items-center mx-auto w-full">
                <h1 class="md:text-4xl text-2xl font-bold mb-1">Login to Your Account</h1>
                <p class="md:text-lg text-[#545454] mb-8">Enter your credentials to continue</p>

                <form class="space-y-4 flex flex-col items-center md:w-lg w-full" method='post' id="sign-form"
                    action="">
                    <div class="w-full">
                        <input type="text" id="email" name="email" placeholder="Enter your email..." required
                            class="block w-full px-6 py-4 text-[#262626] bg-[#d9d9d9] rounded-full focus:outline-none focus:ring-1 focus:ring-[#545454]"
                            value="<?php if ($_SERVER['REQUEST_METHOD'] === 'POST')
                                echo $email ?>" />

                        </div>

                        <div class="w-full">
                            <input type="password" id="password" name="password" placeholder="Enter your password..."
                                required
                                class="block w-full px-6 py-4 text-[#262626] bg-[#d9d9d9] rounded-full focus:outline-none focus:ring-1 focus:ring-[#545454]" />
                            <div class="h-6">
                                <?php
                            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                                if ($user && !$password_is_verified) {
                                    ?>
                                    <span class="block text-red-500 font-medium text-xs ml-6 mt-1">Incorrect password. Please
                                        try
                                        again.</span>
                                    <?php
                                }
                            }
                            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                                if (!$user) {
                                    ?>
                                    <span class="block text-red-500 font-medium text-xs ml-6 mt-1">Unrecognized email. Please
                                        use your corporate email.</span>
                                    <?php
                                }
                            }
                            ?>
                        </div>
                    </div>

                    <!-- Sign In Button -->
                    <button id="login-btn" type="submit"
                        class="w-40 mt-2 px-5 py-2.5 h-12 cursor-pointer bg-black text-white font-bold rounded-2xl hover:bg-[#262626] transition-colors flex items-center justify-center gap-2">
                        <span id="signBtn">Sign In</span>
                        <svg id="signLoader" class="hidden w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4">
                            </circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path>
                        </svg>
                    </button>


                    <div class="flex items-center">

                        <div class="w-full mt-6  md:hidden">
                            Forgot your password?
                            <span id="forgot-password-link-2"
                                class="text-blue-500 underline hover:text-gray-200 hover:underline font-medium cursor-pointer">
                                Click here
                            </span>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <!-- Right side: Branding (hidden on small screens) -->
        <div class="hidden lg:flex flex-col lg:w-1/3 items-center justify-center bg-black text-white p-8">
            <div class="text-left pl-4">
                <h2 class="text-4xl font-bold mb-2">Welcome back!</h2>
                <p class="text-2xl pl-4">You can sign in to access
                    your existing account.</p>
            </div>
            <div class="w-full md:block text-sm hidden mt-6 pl-8">
                Forgot your password?
                <span id="forgot-password-link"
                    class="text-blue-500 underline hover:text-gray-200 hover:underline font-medium cursor-pointer">
                    Click here
                </span>
            </div>
        </div>
    </main>


    <!-- one whole modal overlay -->
    <div id="forget-pass"
        class="fixed flex items-center justify-center top-0 left-0 w-full h-full bg-gray-100/60 backdrop-blur-lg hidden">


        <!-- Forget password modal -->
        <div id="email-modal" class="w-10/12 md:w-90 p-2 flex-col bg-white rounded-lg shadow flex hidden relative">
            <!-- Close Button -->
            <button onclick="closeEmailModal()"
                class="absolute cursor-pointer top-2 right-2 text-gray-500 hover:text-gray-700">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414
            1.414L11.414 10l4.293 4.293a1 1 0 01-1.414
            1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586
            10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
            </button>

            <form id="verify-email-form" action="" method="POST" class="w-full flex flex-col items-center p-2">
                <div class="w-full mb-2">
                    <label for="verify-email" class="font-semibold">Enter your email account:</label>
                </div>
                <input type="email" id="verify-email" name="email"
                    class="w-full pl-2 py-1 border rounded focus:outline-none mb-8" autocomplete="off" required>
                <button id="send-btn" type="button" onclick="verifyEmail()"
                    class="rounded bg-gray-700 h-8 w-1/3 hover:bg-gray-800 cursor-pointer text-white px-2 py-1 font-semibold flex items-center justify-center gap-2">
                    <span id="send-text">Send OTP</span>
                    <svg id="send-loader" class="hidden w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4">
                        </circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path>
                    </svg>
                </button>
            </form>
        </div>



        <!-- OTP modal -->
        <div id="otp-modal"
            class="flex flex-col items-center w-10/12 md:w-90 px-4 py-2 bg-white rounded-md shadow-lg hidden">
            <div class="mt-3 text-3xl font-bold text-center">OTP Verification</div>
            <form id="otp-form" action="includes/verify_otp.php" method="POST"
                class="flex flex-col items-center justify-center w-full">
                <input id="otp-email" type="hidden" name="email">
                <div class="flex justify-between w-3/4 px-4 h-fit mt-7">
                    <input id="digit-1"
                        class="w-10 h-10 text-2xl text-center bg-white border border-gray-400 rounded-md shadow-lg focus:outline-gray-700"
                        autocomplete="one-time-code" maxlength="1" type="tel"
                        onkeypress='return event.charCode >= 48 && event.charCode <= 57'>
                    <input id="digit-2"
                        class="w-10 h-10 text-2xl text-center bg-white border border-gray-400 rounded-md shadow-lg focus:outline-gray-700"
                        autocomplete="one-time-code" maxlength="1" type="tel"
                        onkeypress='return event.charCode >= 48 && event.charCode <= 57'>
                    <input id="digit-3"
                        class="w-10 h-10 text-2xl text-center bg-white border border-gray-400 rounded-md shadow-lg focus:outline-gray-700"
                        autocomplete="one-time-code" maxlength="1" type="tel"
                        onkeypress='return event.charCode >= 48 && event.charCode <= 57'>
                    <input id="digit-4"
                        class="w-10 h-10 text-2xl text-center bg-white border border-gray-400 rounded-md shadow-lg focus:outline-gray-700"
                        autocomplete="one-time-code" maxlength="1" type="tel"
                        onkeypress='return event.charCode >= 48 && event.charCode <= 57'>
                </div>
                <div class="flex flex-wrap justify-center w-3/4 mt-4 mb-2 text-xs text-center text-zinc-500">
                    Please enter the 4-digit one-time-password (OTP) we sent to your email to verify. OTP expires after
                    5 minutes.
                </div>

                <button id="otp-btn" type="button" onclick="verifyOTP()"
                    class="rounded bg-gray-700 h-8 w-1/4 hover:bg-gray-800 cursor-pointer text-white px-2 py-1 font-semibold flex items-center justify-center gap-2">
                    <span id="otp-text">Submit</span>
                    <svg id="otp-loader" class=" hidden w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4">
                        </circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path>
                    </svg>
                </button>
            </form>
        </div>



        <!-- Change password modal -->
        <div id="password-modal"
            class="flex flex-col items-center w-10/12 md:w-90 px-6 py-2 bg-white rounded-md shadow-lg hidden">
            <div class="w-full py-1 text-3xl font-bold text-center h-fit">Change Password</div>
            <div id="password-content" class="flex w-full">
                <form id="password-form" action="includes/change_password.php" method="POST"
                    class="flex flex-col w-full mt-4">
                    <input id="pass-email" type="hidden" name="email">
                    <label for="pass1CP" class=" text-zinc-700">
                        Enter your new password:
                    </label>
                    <input id="pass1CP" type="password" name="password" required
                        class="w-full px-2 py-1 mt-2 border border-gray-700 rounded-md focus:outline-none">
                    <label for="pass2CP" class=" text-zinc-700">
                        Re-enter your password:
                    </label>
                    <input id="pass2CP" type="password" name="pass2" required
                        class="w-full px-2 py-1 mt-2 border border-gray-700 rounded-md focus:outline-none">
                    <span id="pass-err" class="text-xs mt-2 w-full text-end text-red-500 invisible">This is an error
                        message</span>
                    <div class="flex justify-center mt-4 mb-2">
                        <button id="password-btn" type="submit"
                            class="cursor-pointer bg-gray-700 py-1 text-md text-white mt-2 rounded-full w-[9rem] font-semibold hover:bg-gray-800">Confirm</button>
                    </div>
                </form>
            </div>
        </div>

    </div>


    <!-- Loader -->
    <div id="loader"
        class="fixed top-0 w-full h-full bg-gray-300/50 backdrop-blur-sm justify-center items-center hidden z-50">
        <div class="w-16 h-16 border-6 border-t-gray-800 border-white rounded-full animate-spin"></div>
    </div>

    <!-- Notification messsage -->
    <div id="message"
        class="mb-4 hidden w-96 absolute top-32 left-1/2 transform -translate-x-1/2 p-3 rounded text-center z-50">
    </div>
</body>

<script>
    function closeEmailModal() {
        $('#forget-pass').addClass('hidden');
        $('#verify-email-form')[0].reset();
    }


    function showNotification(type, msg) {
        let bg = (type === 'success')
            ? 'bg-green-100 text-green-700 border border-green-400'
            : 'bg-red-100 text-red-700 border border-red-400';

        $('#message')
            .attr('class', `mb-4 w-96 fixed top-32 left-1/2 transform -translate-x-1/2 p-3 rounded text-center z-50 ${bg}`)
            .text(msg)
            .removeClass('hidden');

        setTimeout(() => {
            $('#message').addClass('hidden');
        }, 3000);
    }

    function isStrongPassword(pw) {
        const passErr = $('#pass-err');

        if (pw.length < 8) {
            passErr.text('Password must be at least 8 characters long').removeClass("invisible");
            return false;
        }
        if (!/[A-Z]/.test(pw)) {
            passErr.text('Password must contain at least 1 uppercase letter').removeClass("invisible");
            return false;
        }
        if (!/[a-z]/.test(pw)) {
            passErr.text('Password must contain at least 1 lowercase letter').removeClass("invisible");
            return false;
        }
        if (!/[0-9]/.test(pw)) {
            passErr.text('Password must contain at least 1 number').removeClass("invisible");
            return false;
        }
        if (!/[\W_]/.test(pw)) {
            passErr.text('Password must contain at least 1 special character').removeClass("invisible");
            return false;
        }
        return true;
    }


    function verifyEmail() {
        let formData = new FormData($('#verify-email-form')[0]);
        let email = $('#verify-email').val();

        // Disable button + show loader
        $('#send-btn').attr('disabled', true).addClass('opacity-50 cursor-not-allowed');
        $('#send-loader').removeClass('hidden');
        $('#send-text').addClass('hidden');

        $.ajax({
            url: 'includes/verify-email.php',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            dataType: 'json',
            success: function (response) {
                // Enable button + hide loader
                $('#send-btn').attr('disabled', false).removeClass('opacity-50 cursor-not-allowed');
                $('#send-text').text('Send OTP');
                $('#send-text').removeClass('hidden');
                $('#send-loader').addClass('hidden');

                if (response.status === 'success') {
                    showNotification("success", response.message);
                    $('#otp-email').val(email);
                    $('#email-modal').addClass('hidden');
                    $('#otp-modal').removeClass('hidden');
                    $('#verify-email-form')[0].reset();
                } else {
                    showNotification("error", response.message);
                }
            },
            error: function (xhr, status, error) {
                // Enable button + hide loader
                $('#send-btn').attr('disabled', false).removeClass('opacity-50 cursor-not-allowed');
                $('#send-text').text('Send OTP');
                $('#send-text').removeClass('hidden');
                $('#send-loader').addClass('hidden');


                showNotification("error", error);
            }
        });
    }


    function verifyOTP() {
        let email = $('#otp-email').val();
        let otp = $('#digit-1').val() + $('#digit-2').val() + $('#digit-3').val() + $('#digit-4').val();

        // Disable button + show loader
        $('#otp-btn').attr('disabled', true).addClass('opacity-50 cursor-not-allowed');
        $('#otp-loader').removeClass('hidden');
        $('#otp-text').addClass('hidden');



        $.ajax({
            url: 'includes/verify-otp.php',
            method: 'POST',
            data: { email: email, code: otp },
            dataType: 'json',
            success: function (response) {
                // Enable button + hide loader
                $('#otp-btn').attr('disabled', false).removeClass('opacity-50 cursor-not-allowed');
                $('#otp-text').text('Submit');
                $('#otp-text').removeClass('hidden');
                $('#otp-loader').addClass('hidden');

                if (response.status === 'success') {
                    showNotification("success", response.message);
                    $('#pass-email').val(email);
                    $('#otp-modal').addClass('hidden');
                    $('#password-modal').removeClass('hidden');
                } else {
                    showNotification("error", response.message);
                }
            },
            error: function (xhr, status, error) {
                // Enable button + hide loader
                $('#otp-btn').attr('disabled', false).removeClass('opacity-50 cursor-not-allowed');
                $('#otp-text').text('Submit');
                $('#otp-text').removeClass('hidden');
                $('#otp-loader').addClass('hidden');

                showNotification("error", error);
            }
        });
    }

    function verifyPass() {
        let email = $('#pass-email').val();
        let pass1 = $('#pass1CP').val();
        let pass2 = $('#pass2CP').val();

        const passErr = $('#pass-err');

        if (!isStrongPassword(pass1)) {
            return;
        }


        if (pass1 !== pass2) {
            passErr.text("Passwords do not match.").removeClass("invisible");
            return;
        }

        passErr.addClass("invisible");
        $('#loader').removeClass('hidden').addClass('flex');

        $.ajax({
            url: 'includes/verify-password.php',
            method: 'POST',
            data: { email: email, password: pass1 },
            dataType: 'json',
            success: function (response) {
                $('#loader').addClass('hidden').removeClass('flex');
                if (response.status === 'success') {
                    showNotification("success", response.message);
                    $('#forget-pass').addClass('hidden');
                    $('#password-form')[0].reset();
                    $('#password-modal').addClass('hidden');
                } else {
                    showNotification("error", response.message);
                }
            },
            error: function (xhr, status, error) {
                $('#loader').addClass('hidden').removeClass('flex');
                showNotification("error", error);
            }
        });
    }

    $(document).ready(function () {
        $('#sign-form').on('submit', function () {
            // Disable button + show loader
            $('#login-btn').attr('disabled', true).addClass('opacity-50 cursor-not-allowed');
            $('#signLoader').removeClass('hidden');
            $('#signBtn').addClass('hidden');
        });

        $('#forgot-password-link').on('click', function (e) {
            e.preventDefault();
            $('#forget-pass').removeClass('hidden');
            $('#email-modal').removeClass('hidden');
        });
        $('#forgot-password-link-2').on('click', function (e) {
            e.preventDefault();
            $('#forget-pass').removeClass('hidden');
            $('#email-modal').removeClass('hidden');
        });


        $("input[id^='digit-']").on("keyup", function (e) {
            if (e.key === "Backspace" && $(this).val() === "") {
                $(this).prev("input").focus();
            } else if ($(this).val().length === 1) {
                $(this).next("input").focus();
            }
        });

        $('#verify-email-form').on('submit', function (e) {
            e.preventDefault();
            verifyEmail();
        });

        $('#otp-form').on('submit', function (e) {
            e.preventDefault();
            verifyOTP();
        });

        $('#password-form').on('submit', function (e) {
            e.preventDefault();
            verifyPass();
        });

        $('#error .fa-xmark, #success .fa-xmark').on('click', function () {
            $(this).closest('div').fadeOut(200, function () {
                $(this).addClass('hidden').removeClass('flex').show();
            });
        });
    });

</script>

</html>
