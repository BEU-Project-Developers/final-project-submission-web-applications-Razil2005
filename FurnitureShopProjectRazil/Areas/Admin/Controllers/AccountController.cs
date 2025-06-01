using FurnitureShopProjectRazil.Data;
using FurnitureShopProjectRazil.Models;
using FurnitureShopProjectRazil.Services;
using FurnitureShopProjectRazil.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using System; // DateTime, Guid üçün
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using FurnitureShopProjectRazil.Interfaces; // HtmlEncoder üçün

namespace CaterManagementSystem.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "Admin")]
    public class AccountController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IPasswordService _passwordService;
        private readonly IEmailSender _emailSender; // Admin qeydiyyatı üçün e-poçt təsdiqi istəsəniz
        private readonly ILogger<AccountController> _logger;

        public AccountController(AppDbContext context,
                                 IPasswordService passwordService,
                                 IEmailSender emailSender, // Əlavə edildi
                                 ILogger<AccountController> logger)
        {
            _context = context;
            _passwordService = passwordService;
            _emailSender = emailSender; // Təyin edildi
            _logger = logger;
        }

        // GET: /Admin/Account/Login
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl ?? Url.Action("Index", "Dashboard", new { Area = "Admin" });
            return View(); // Areas/Admin/Views/Account/Login.cshtml
        }

        // POST: /Admin/Account/Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl ?? Url.Action("Index", "Dashboard", new { Area = "Admin" });

            if (ModelState.IsValid)
            {
                var user = await _context.Users
                                         .Include(u => u.UserRoles!)
                                             .ThenInclude(ur => ur.Role)
                                         .FirstOrDefaultAsync(u => (u.Username == model.UsernameOrEmail || u.Email == model.UsernameOrEmail));

                if (user != null && _passwordService.VerifyPasswordHash(model.Password, user.PasswordHash, user.PasswordSalt))
                {
                    // Admin rolunu yoxla
                    bool isAdmin = user.UserRoles.Any(ur => ur.Role != null && ur.Role.Name == "Admin");

                    if (!isAdmin)
                    {
                        _logger.LogWarning("Login attempt for non-admin user '{UserName}' to admin panel.", model.UsernameOrEmail);
                        ModelState.AddModelError(string.Empty, "Bu paneldən yalnız administratorlar daxil ola bilər.");
                        return View(model);
                    }

                    if (!user.EmailConfirmed) // E-poçt təsdiqi adminlər üçün də vacibdirsə
                    {
                        ModelState.AddModelError(string.Empty, "Daxil olmaq üçün e-poçt ünvanınızı təsdiqləməlisiniz.");
                        return View(model);
                    }

                    await SignInAdminAsync(user, model.RememberMe);
                    _logger.LogInformation("Admin user '{UserName}' logged in successfully.", user.Username);

                    if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                        return Redirect(returnUrl);

                    return RedirectToAction("Index", "Dashboard", new { Area = "Admin" });
                }
                _logger.LogWarning("Failed admin login attempt for '{UserName}'.", model.UsernameOrEmail);
                ModelState.AddModelError(string.Empty, "Yanlış istifadəçi adı/e-poçt və ya şifrə.");
            }
            return View(model);
        }

        private async Task SignInAdminAsync(User user, bool isPersistent)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.GivenName, user.FullName ?? string.Empty)
            };

            // Admin üçün xüsusi claim-lər və ya profil şəkli əlavə edilə bilər (əgər UserDetails istifadə olunursa)
            var userDetails = await _context.UserDetails.FirstOrDefaultAsync(ud => ud.UserId == user.Id);
            string profilePicturePath = userDetails?.ImagePath ?? "default-avatar.png"; // Default admin avatarı
            claims.Add(new Claim("ProfilePicture", profilePicturePath));

            foreach (var userRole in user.UserRoles)
            {
                if (userRole.Role != null)
                {
                    claims.Add(new Claim(ClaimTypes.Role, userRole.Role.Name));
                }
            }

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            // Adminlər üçün fərqli cookie adı və ya xüsusiyyətləri təyin etmək olar, amma sadəlik üçün eyni sxemi istifadə edirik.
            // Əgər admin və adi istifadəçi sessiyalarını tamamilə ayırmaq istəyirsinizsə, fərqli AuthenticationScheme düşünülə bilər.
            var authProperties = new AuthenticationProperties { IsPersistent = isPersistent };

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);
        }


        // GET: /Admin/Account/Register
        [HttpGet]
        public IActionResult Register()
        {
            // Admin qeydiyyatını məhdudlaşdırmaq üçün burada yoxlamalar ola bilər
            // Məsələn, yalnız xüsusi bir tokenlə və ya mövcud admin tərəfindən yönləndirildikdə.
            // Sadəlik üçün indi açıqdır.
            return View(); // Areas/Admin/Views/Account/Register.cshtml
        }

        // POST: /Admin/Account/Register
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
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

                if (!ModelState.IsValid) return View(model);

                _passwordService.CreatePasswordHash(model.Password, out byte[] passwordHash, out byte[] passwordSalt);

                var user = new User
                {
                    Username = model.Username,
                    Email = model.Email,
                    FullName = model.FullName,
                    PasswordHash = passwordHash,
                    PasswordSalt = passwordSalt,
                    EmailConfirmed = false, // E-poçt təsdiqi tələb edilsin mi?
                    RegistrationDate = DateTime.UtcNow,
                    EmailConfirmationToken = Guid.NewGuid().ToString("N"),
                    EmailConfirmationTokenExpiry = DateTime.UtcNow.AddDays(1)
                };

                // DİQQƏT: Yeni qeydiyyatdan keçən istifadəçiyə AVTOMATİK OLARAQ "Admin" ROLU VERİLMƏMƏLİDİR!
                // Bu, təhlükəsizlik riski yaradır.
                // Rolu ya ayrıca bir proseslə təyin edin, ya da default olaraq "PendingAdmin" kimi bir rol verin.
                // Mən burada default "User" rolunu verəcəyəm, sonra admin onu "Admin" roluna yüksəltməlidir.
                var defaultRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "User"); // Və ya "PendingAdmin"
                if (defaultRole == null)
                {
                    _logger.LogError("Default role for admin registration not found.");
                    ModelState.AddModelError(string.Empty, "Qeydiyyat zamanı sistem xətası. Administrator ilə əlaqə saxlayın.");
                    return View(model);
                }
                user.UserRoles.Add(new UserRole { Role = defaultRole });

                var userDetails = new UserDetails { User = user, ImagePath = "default-avatar.png" };

                using (var transaction = await _context.Database.BeginTransactionAsync())
                {
                    try
                    {
                        _context.Users.Add(user);
                        _context.UserDetails.Add(userDetails);
                        await _context.SaveChangesAsync();

                        // Admin qeydiyyatı üçün e-poçt təsdiqi göndərilsinmi?
                        var callbackUrl = Url.Action("ConfirmEmail", "Account", // Əsas AccountController-dakı ConfirmEmail-i istifadə edə bilər
                                           new { userId = user.Id, token = user.EmailConfirmationToken, Area = "" }, // Area="" əsas Controller-ə yönləndirir
                                           protocol: Request.Scheme);

                        if (!string.IsNullOrEmpty(callbackUrl))
                        {
                            await _emailSender.SendEmailAsync(model.Email, "Admin Hesabınızı Təsdiqləyin",
                                $"Zəhmət olmasa admin hesabınızı <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>buraya</a> klikləyərək təsdiqləyin.");
                        }

                        await transaction.CommitAsync();
                        _logger.LogInformation("New potential admin user '{UserName}' registered.", user.Username);
                        TempData["SuccessMessage"] = "Qeydiyyat uğurla tamamlandı. E-poçt ünvanınızı təsdiqləyin və hesabınızın admin tərəfindən aktivləşdirilməsini gözləyin.";
                        return RedirectToAction(nameof(Login)); // Və ya xüsusi bir təsdiq səhifəsinə
                    }
                    // ... (catch blokları əsas AccountController-dakı kimi) ...
                    catch (DbUpdateException dbEx)
                    {
                        await transaction.RollbackAsync();
                        _logger.LogError(dbEx, "Database error during admin registration for {Email}. InnerException: {InnerEx}", model.Email, dbEx.InnerException?.Message);
                        ModelState.AddModelError(string.Empty, "Qeydiyyat zamanı verilənlər bazası xətası.");
                    }
                    catch (Exception ex)
                    {
                        await transaction.RollbackAsync();
                        _logger.LogError(ex, "General error during admin registration for {Email}. Details: {ExceptionDetails}", model.Email, ex.ToString());
                        ModelState.AddModelError(string.Empty, "Qeydiyyat zamanı xəta baş verdi.");
                    }
                }
            }
            return View(model);
        }

        // Admin üçün Logout (əgər lazımdırsa, əsas Logout-dan fərqli davranmalıdırmı?)
        // Adətən eyni Logout action-ı həm admin, həm də istifadəçi üçün işləyir.
        // Əgər xüsusi bir yönləndirmə və ya mesaj lazımdırsa, buraya əlavə edilə bilər.
        // [HttpPost]
        // [ValidateAntiForgeryToken]
        // public async Task<IActionResult> Logout()
        // {
        //     await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        //     _logger.LogInformation("Admin user logged out.");
        //     return RedirectToAction("Login", "Account", new { Area = "Admin" }); // Admin login səhifəsinə
        // }
    }
}