using FurnitureShopProjectRazil.Data;
using FurnitureShopProjectRazil.Interfaces;
using FurnitureShopProjectRazil.Models;
using FurnitureShopProjectRazil.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq; // .Any() üçün əlavə edildi
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace FurnitureShopProjectRazil.Controllers
{
    public class AccountController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IPasswordService _passwordService;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<AccountController> _logger;

        public AccountController(AppDbContext context,
                                 IPasswordService passwordService,
                                 IWebHostEnvironment webHostEnvironment,
                                 IEmailSender emailSender,
                                 ILogger<AccountController> logger)
        {
            _context = context;
            _passwordService = passwordService;
            _webHostEnvironment = webHostEnvironment;
            _emailSender = emailSender;
            _logger = logger;
        }

        // GET: /Account/Register
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string? returnUrl = null)
        {
            if (User.Identity?.IsAuthenticated ?? false)
            {
                return RedirectToLocal(returnUrl);
            }
            ViewData["ReturnUrl"] = returnUrl;
            return View(new RegisterViewModel());
        }

        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (User.Identity?.IsAuthenticated ?? false)
            {
                return RedirectToLocal(returnUrl);
            }

            if (ModelState.IsValid)
            {
                if (await _context.Users.AnyAsync(u => u.Username == model.Username))
                {
                    ModelState.AddModelError(nameof(model.Username), "Bu istifadəçi adı artıq mövcuddur.");
                }
                if (await _context.Users.AnyAsync(u => u.Email == model.Email))
                {
                    ModelState.AddModelError(nameof(model.Email), "Bu e-poçt ünvanı artıq qeydiyyatdan keçib.");
                }

                if (!ModelState.IsValid)
                {
                    return View(model);
                }

                _passwordService.CreatePasswordHash(model.Password, out byte[] passwordHash, out byte[] passwordSalt);

                var user = new User
                {
                    Username = model.Username,
                    Email = model.Email,
                    FullName = model.FullName,
                    PasswordHash = passwordHash,
                    PasswordSalt = passwordSalt,
                    ImagePath = "images/default-avatar.png",
                    EmailConfirmed = false,
                    EmailConfirmationToken = Guid.NewGuid().ToString(),
                    EmailConfirmationTokenExpiry = DateTime.UtcNow.AddDays(1)
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                var defaultRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "User"); // DÜZƏLDİLDİ: r.Rolename
                if (defaultRole == null)
                {
                    _logger.LogError("Default role 'User' not found in the database. Seeding might have failed.");
                    ModelState.AddModelError("", "Qeydiyyat zamanı sistem xətası. Zəhmət olmasa, daha sonra cəhd edin.");
                    _context.Users.Remove(user);
                    await _context.SaveChangesAsync();
                    return View(model);
                }
                _context.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = defaultRole.Id });
                await _context.SaveChangesAsync();

                _logger.LogInformation($"User {user.Username} registered successfully and assigned 'User' role.");

                var tokenForUrl = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(user.EmailConfirmationToken!));
                var callbackUrl = Url.Action(nameof(ConfirmEmail), "Account",
                    new { userId = user.Id.ToString(), token = tokenForUrl }, protocol: Request.Scheme);

                if (!string.IsNullOrEmpty(callbackUrl))
                {
                    try
                    {
                        await _emailSender.SendEmailAsync(model.Email, "Hesabınızı Təsdiqləyin - FurnitureShop",
                            $"Hörmətli {user.FullName},<br><br>Hesabınızı təsdiqləmək üçün zəhmət olmasa <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>bura klikləyin</a>.<br><br>Əgər bu qeydiyyatı siz etməmisinizsə, bu e-poçta məhəl qoymayın.<br><br>Hörmətlə,<br>FurnitureShop Dəstək Komandası");
                        _logger.LogInformation($"Confirmation email sent to {user.Email}.");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Failed to send confirmation email to {user.Email}.");
                    }
                }
                else
                {
                    _logger.LogError($"Could not generate callback URL for email confirmation for user {user.Email}.");
                }
                return RedirectToAction(nameof(RegisterConfirmation), new { email = model.Email });
            }
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult RegisterConfirmation(string? email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return RedirectToAction(nameof(Register));
            }
            ViewBag.Email = email;
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string? userId, string? token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                TempData["ErrorMessage"] = "E-poçt təsdiq linki natamamdır.";
                return RedirectToAction("Index", "Home");
            }

            if (!int.TryParse(userId, out int idAsInt))
            {
                ViewBag.Message = "İstifadəçi ID-si düzgün formatda deyil.";
                return View();
            }

            var user = await _context.Users.FindAsync(idAsInt);
            if (user == null)
            {
                ViewBag.Message = "E-poçt təsdiq linki etibarsızdır (istifadəçi tapılmadı).";
                return View();
            }

            if (user.EmailConfirmed)
            {
                ViewBag.Message = "E-poçt ünvanınız artıq təsdiqlənib.";
                return View();
            }

            try
            {
                var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
                if (user.EmailConfirmationToken == decodedToken &&
                    user.EmailConfirmationTokenExpiry.HasValue &&
                    user.EmailConfirmationTokenExpiry.Value > DateTime.UtcNow)
                {
                    user.EmailConfirmed = true;
                    user.EmailConfirmationToken = null;
                    user.EmailConfirmationTokenExpiry = null;
                    _context.Users.Update(user);
                    await _context.SaveChangesAsync();
                    ViewBag.Message = "E-poçt ünvanınız uğurla təsdiqləndi! İndi daxil ola bilərsiniz.";
                    _logger.LogInformation($"Email confirmed successfully for user {user.Email}.");
                }
                else if (user.EmailConfirmationTokenExpiry.HasValue && user.EmailConfirmationTokenExpiry.Value <= DateTime.UtcNow)
                {
                    ViewBag.Message = "E-poçt təsdiq linkinin vaxtı bitib. Zəhmət olmasa, yenidən tələb edin.";
                    _logger.LogWarning($"Email confirmation token expired for user {user.Email}.");
                }
                else
                {
                    ViewBag.Message = "E-poçt təsdiq linki etibarsızdır.";
                    _logger.LogWarning($"Invalid email confirmation token for user {user.Email}. Provided token part (from URL): {token}");
                }
            }
            catch (FormatException ex)
            {
                _logger.LogError(ex, $"Error decoding email confirmation token for user {user.Email}. Token from URL: {token}");
                ViewBag.Message = "E-poçt təsdiq linki etibarsız formatdadır.";
            }
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? returnUrl = null)
        {
            if (User.Identity?.IsAuthenticated ?? false)
            {
                return RedirectToLocal(returnUrl);
            }
            ViewData["ReturnUrl"] = returnUrl;
            return View(new LoginViewModel());
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (User.Identity?.IsAuthenticated ?? false)
            {
                return RedirectToLocal(returnUrl);
            }

            if (ModelState.IsValid)
            {
                var user = await _context.Users
                                         .Include(u => u.UserRoles!)
                                             .ThenInclude(ur => ur.Role!)
                                         .FirstOrDefaultAsync(u => u.Username == model.UsernameOrEmail || u.Email == model.UsernameOrEmail);

                if (user == null || user.PasswordHash == null || user.PasswordSalt == null ||
                    !_passwordService.VerifyPasswordHash(model.Password, user.PasswordHash, user.PasswordSalt))
                {
                    ModelState.AddModelError(string.Empty, "İstifadəçi adı/e-poçt və ya parol yanlışdır.");
                    return View(model);
                }

                if (!user.EmailConfirmed)
                {
                    ModelState.AddModelError(string.Empty, "Daxil olmaq üçün e-poçt ünvanınızı təsdiqləməlisiniz.");
                    return View(model);
                }

                await SignInUserAsync(user, model.RememberMe);
                _logger.LogInformation($"User {user.Username} logged in successfully.");
                return RedirectToLocal(returnUrl);
            }
            return View(model);
        }

        private async Task SignInUserAsync(User user, bool isPersistent)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.GivenName, user.FullName)
            };

            if (!string.IsNullOrEmpty(user.ImagePath))
            {
                claims.Add(new Claim("ImagePath", user.ImagePath));
            }

            if (user.UserRoles != null)
            {
                foreach (var userRole in user.UserRoles)
                {
                    if (userRole.Role != null && !string.IsNullOrEmpty(userRole.Role.Name)) // DÜZƏLDİLDİ: Rolename
                    {
                        claims.Add(new Claim(ClaimTypes.Role, userRole.Role.Name)); // DÜZƏLDİLDİ: Rolename
                    }
                }
            }

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                IsPersistent = isPersistent,
                ExpiresUtc = isPersistent ? DateTime.UtcNow.AddDays(30) : (DateTime?)null
            };

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                          new ClaimsPrincipal(claimsIdentity),
                                          authProperties);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userName = User.Identity?.Name;
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _logger.LogInformation($"User {userName} logged out.");
            TempData["SuccessMessage"] = "Sistemdən uğurla çıxış etdiniz.";
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> EditProfile()
        {
            var userIdStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdStr) || !int.TryParse(userIdStr, out int userId))
            {
                _logger.LogWarning("EditProfile GET: User ID not found in claims or invalid format.");
                return Challenge();
            }

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                _logger.LogWarning($"EditProfile GET: User with ID {userId} not found.");
                return NotFound();
            }

            var viewModel = new EditProfileViewModel
            {
                UserId = user.Id,
                Username = user.Username,
                FullName = user.FullName,
                CurrentImagePath = user.ImagePath
            };
            return View(viewModel);
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditProfile(EditProfileViewModel model)
        {
            var currentUserIdStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(currentUserIdStr) || !int.TryParse(currentUserIdStr, out int currentAuthUserId) || model.UserId != currentAuthUserId)
            {
                _logger.LogWarning($"EditProfile POST: Attempt to edit profile for user {model.UserId} by unauthenticated or unauthorized user.");
                return Forbid();
            }

            if (string.IsNullOrWhiteSpace(model.FullName)) // FullName boş ola bilməz
            {
                ModelState.AddModelError(nameof(model.FullName), "Tam ad tələb olunur.");
            }
            if (string.IsNullOrWhiteSpace(model.Username)) // Username boş ola bilməz
            {
                ModelState.AddModelError(nameof(model.Username), "İstifadəçi adı tələb olunur.");
            }


            if (!ModelState.IsValid)
            {
                var userForPath = await _context.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == model.UserId);
                model.CurrentImagePath = userForPath?.ImagePath;
                return View(model);
            }

            var userToUpdate = await _context.Users.FindAsync(model.UserId);
            if (userToUpdate == null)
            {
                _logger.LogWarning($"EditProfile POST: User with ID {model.UserId} not found for update.");
                return NotFound();
            }

            if (userToUpdate.Username != model.Username && await _context.Users.AnyAsync(u => u.Username == model.Username && u.Id != model.UserId))
            {
                ModelState.AddModelError(nameof(model.Username), "Bu istifadəçi adı artıq mövcuddur.");
                model.CurrentImagePath = userToUpdate.ImagePath;
                return View(model);
            }

            userToUpdate.Username = model.Username;
            userToUpdate.FullName = model.FullName;
            bool claimsNeedRefresh = User.FindFirstValue(ClaimTypes.Name) != userToUpdate.Username ||
                                     User.FindFirstValue(ClaimTypes.GivenName) != userToUpdate.FullName;

            if (model.Photo != null && model.Photo.Length > 0)
            {
                if (!string.IsNullOrEmpty(userToUpdate.ImagePath) && !userToUpdate.ImagePath.EndsWith("default-avatar.png"))
                {
                    var oldPhysicalPath = Path.Combine(_webHostEnvironment.WebRootPath, userToUpdate.ImagePath.TrimStart('/', '\\'));
                    if (System.IO.File.Exists(oldPhysicalPath))
                    {
                        try { System.IO.File.Delete(oldPhysicalPath); }
                        catch (IOException ex) { _logger.LogError(ex, $"Could not delete old profile image: {oldPhysicalPath}"); }
                    }
                }

                string uploadsFolder = Path.Combine(_webHostEnvironment.WebRootPath, "images", "profiles");
                if (!Directory.Exists(uploadsFolder)) Directory.CreateDirectory(uploadsFolder);

                string uniqueFileName = Guid.NewGuid().ToString() + Path.GetExtension(model.Photo.FileName);
                string newPhysicalPath = Path.Combine(uploadsFolder, uniqueFileName);

                try
                {
                    using (var fileStream = new FileStream(newPhysicalPath, FileMode.Create))
                    {
                        await model.Photo.CopyToAsync(fileStream);
                    }
                    userToUpdate.ImagePath = $"images/profiles/{uniqueFileName}";
                    if (User.FindFirstValue("ImagePath") != userToUpdate.ImagePath) claimsNeedRefresh = true;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error uploading new profile image for user {userToUpdate.Username}.");
                    ModelState.AddModelError(nameof(model.Photo), "Şəkil yüklənərkən xəta baş verdi.");
                    model.CurrentImagePath = userToUpdate.ImagePath;
                    return View(model);
                }
            }

            try
            {
                _context.Users.Update(userToUpdate);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "Profil məlumatlarınız uğurla yeniləndi.";
                _logger.LogInformation($"Profile updated for user {userToUpdate.Username}.");

                if (claimsNeedRefresh)
                {
                    var authResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    bool isPersistent = authResult?.Properties?.IsPersistent ?? (User.Identity?.IsAuthenticated ?? false);


                    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await SignInUserAsync(userToUpdate, isPersistent);
                    _logger.LogInformation($"Claims updated and user re-signed in for {userToUpdate.Username}.");
                }
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogError(ex, $"Concurrency error while updating profile for user {userToUpdate.Username}.");
                ModelState.AddModelError("", "Məlumatlar yenilənərkən xəta baş verdi. Səhifəni yeniləyib təkrar cəhd edin.");
                model.CurrentImagePath = (await _context.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == model.UserId))?.ImagePath;
                return View(model);
            }
            return RedirectToAction(nameof(EditProfile));
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View(new ForgotPasswordViewModel());
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == model.Email);
                if (user != null && user.EmailConfirmed)
                {
                    user.PasswordResetToken = Guid.NewGuid().ToString();
                    user.PasswordResetTokenExpiryDate = DateTime.UtcNow.AddMinutes(30); // DÜZƏLDİLDİ: PasswordResetTokenExpiry

                    _context.Users.Update(user);
                    await _context.SaveChangesAsync();

                    var tokenForUrl = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(user.PasswordResetToken!));
                    var callbackUrl = Url.Action(nameof(ResetPassword), "Account",
                        new { userId = user.Id.ToString(), token = tokenForUrl }, protocol: Request.Scheme);

                    if (!string.IsNullOrEmpty(callbackUrl))
                    {
                        try
                        {
                            await _emailSender.SendEmailAsync(model.Email, "Parolunuzu Sıfırlayın - FurnitureShop",
                                $"Hörmətli {user.FullName},<br><br>Parolunuzu sıfırlamaq üçün zəhmət olmasa <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>bura klikləyin</a>.<br>Bu link 30 dəqiqə ərzində etibarlıdır.<br><br>Əgər bu tələbi siz etməmisinizsə, bu e-poçta məhəl qoymayın.<br><br>Hörmətlə,<br>FurnitureShop Dəstək Komandası");
                            _logger.LogInformation($"Password reset email sent to {user.Email}.");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Failed to send password reset email to {user.Email}.");
                        }
                    }
                    else
                    {
                        _logger.LogError($"Could not generate callback URL for password reset for user {user.Email}.");
                    }
                }
                else if (user != null && !user.EmailConfirmed)
                {
                    _logger.LogWarning($"Password reset attempt for unconfirmed email: {model.Email}.");
                }
                else
                {
                    _logger.LogWarning($"Password reset attempt for non-existent or unconfirmed email: {model.Email}.");
                }
                TempData["InfoMessage"] = "Əgər daxil etdiyiniz e-poçt ünvanı sistemimizdə mövcuddursa və təsdiqlənibsə, şifrə sıfırlama linki göndərildi. Zəhmət olmasa, e-poçtunuzu yoxlayın.";
                return View("ForgotPasswordConfirmation");
            }
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(string? userId, string? token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                TempData["ErrorMessage"] = "Parol sıfırlama linki natamamdır.";
                return RedirectToAction(nameof(Login));
            }

            if (!int.TryParse(userId, out int idAsInt))
            {
                TempData["ErrorMessage"] = "Parol sıfırlama linki etibarsızdır (istifadəçi ID).";
                return RedirectToAction(nameof(Login));
            }

            var user = await _context.Users.FindAsync(idAsInt);
            string? decodedToken = null;
            try
            {
                decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            }
            catch (FormatException)
            {
                TempData["ErrorMessage"] = "Parol sıfırlama linki etibarsızdır (token formatı).";
                return RedirectToAction(nameof(Login));
            }

            if (user == null || user.PasswordResetToken != decodedToken ||
                !user.PasswordResetTokenExpiryDate.HasValue || user.PasswordResetTokenExpiryDate.Value <= DateTime.UtcNow) // DÜZƏLDİLDİ: PasswordResetTokenExpiry
            {
                TempData["ErrorMessage"] = "Parol sıfırlama linki etibarsızdır və ya vaxtı bitib.";
                return RedirectToAction(nameof(Login));
            }

            var model = new ResetPasswordViewModel { UserId = userId, Token = token };
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (string.IsNullOrEmpty(model.UserId) || !int.TryParse(model.UserId, out int idAsInt))
            {
                ModelState.AddModelError("", "Etibarsız istifadəçi ID-si.");
                return View(model);
            }

            var user = await _context.Users.FindAsync(idAsInt);
            string? decodedToken = null;
            try
            {
                decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(model.Token!));
            }
            catch (FormatException)
            {
                ModelState.AddModelError("", "Etibarsız sıfırlama kodu formatı.");
                return View(model);
            }

            if (user == null || user.PasswordResetToken != decodedToken ||
                !user.PasswordResetTokenExpiryDate.HasValue || user.PasswordResetTokenExpiryDate.Value <= DateTime.UtcNow) // DÜZƏLDİLDİ: PasswordResetTokenExpiry
            {
                ModelState.AddModelError("", "Parol sıfırlama tələbi etibarsızdır və ya vaxtı bitib. Zəhmət olmasa, yenidən cəhd edin.");
                return View(model);
            }

            _passwordService.CreatePasswordHash(model.Password, out byte[] newPasswordHash, out byte[] newPasswordSalt);
            user.PasswordHash = newPasswordHash;
            user.PasswordSalt = newPasswordSalt;
            user.PasswordResetToken = null;
            user.PasswordResetTokenExpiryDate = null; // DÜZƏLDİLDİ: PasswordResetTokenExpiry

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Password reset successfully for user {user.Email}.");
            TempData["SuccessMessage"] = "Parolunuz uğurla dəyişdirildi. İndi yeni parolunuzla daxil ola bilərsiniz.";
            return RedirectToAction(nameof(Login));
        }

        private IActionResult RedirectToLocal(string? returnUrl)
        {
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }
    }
}