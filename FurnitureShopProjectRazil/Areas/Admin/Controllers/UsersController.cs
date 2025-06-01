using Microsoft.AspNetCore.Mvc;
using FurnitureShopProjectRazil.Data;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading.Tasks;
using FurnitureShopProjectRazil.Areas.Admin.ViewModels; // ViewModel üçün
using FurnitureShopProjectRazil.Models; // User, UserDetails, Role, UserRole modelləri üçün
// using Microsoft.AspNetCore.Authorization;

namespace FurnitureShopProjectRazil.Areas.Admin.Controllers
{
    [Area("Admin")]
    // [Authorize(Roles = "Admin")] // Yalnız admin roluna sahib olanlar üçün
    public class UsersController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env; // Şəkil yükləmə üçün UserDetails redaktəsində lazım olacaq

        public UsersController(AppDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }

        // INDEX - İstifadəçilərin siyahısı
        public async Task<IActionResult> Index()
        {
            var users = await _context.Users // DbSet adınız AppUsers olaraq təyin edilib
                .Include(u => u.UserDetails) // Profil şəklini almaq üçün
                .Include(u => u.UserRoles)    // User-in rollarını almaq üçün
                    .ThenInclude(ur => ur.Role) // UserRole-dan sonra Role məlumatını da yüklə
                .OrderBy(u => u.Username)
                .Select(u => new UserViewModel
                {
                    Id = u.Id,
                    UserName = u.Username,
                    Email = u.Email,
                    FirstName = u.FullName,
                    ProfileImagePath = u.UserDetails != null ? u.UserDetails.ImagePath : null, // UserDetails null ola bilər
                    Roles = u.UserRoles.Select(ur => ur.Role.Name).ToList() // İstifadəçinin rollarının adları
                })
                .ToListAsync();

            return View(users);
        }

        // DETAILS - İstifadəçi haqqında ətraflı məlumat (Nümunə)
        [HttpGet]
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var user = await _context.Users
                .Where(u => u.Id == id)
                .Include(u => u.UserDetails)
                .Include(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
                .Select(u => new UserViewModel
                {
                    Id = u.Id,
                    UserName = u.Username,
                    Email = u.Email,
                    FirstName = u.FullName,
                    ProfileImagePath = u.UserDetails != null ? u.UserDetails.ImagePath : null,
                    Roles = u.UserRoles.Select(ur => ur.Role.Name).ToList()
                })
                .FirstOrDefaultAsync();

            if (user == null)
            {
                return NotFound();
            }

            return View(user); // Areas/Admin/Views/Users/Details.cshtml yaratmalısınız
        }


        // UserDetails (şəkil) redaktəsi üçün metodlar əlavə edilə bilər
        // GET: Admin/Users/EditProfileImage/5
        [HttpGet]
        public async Task<IActionResult> EditProfileImage(int? userId)
        {
            if (userId == null) return NotFound();

            var user = await _context.Users.Include(u => u.UserDetails).FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null) return NotFound();

            var userDetails = user.UserDetails ?? new UserDetails { UserId = userId.Value };

            // ViewModel yarada bilərsiniz və ya birbaşa UserDetails-i göndərə bilərsiniz
            // Nümunə üçün UserDetails-i göndəririk:
            return View(userDetails); // Areas/Admin/Views/Users/EditProfileImage.cshtml yaratmalısınız
        }

        // POST: Admin/Users/EditProfileImage
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditProfileImage(UserDetails model)
        {
            if (!ModelState.IsValid)
            {
                // UserId-ni view-a geri göndərmək üçün yenidən yükləyə bilərik,
                // amma modeldə artıq olmalıdır.
                return View(model);
            }

            var userDetails = await _context.UserDetails.FirstOrDefaultAsync(ud => ud.UserId == model.UserId);
            bool isNew = userDetails == null;

            if (isNew)
            {
                userDetails = new UserDetails { UserId = model.UserId };
            }

            if (model.Photo != null && model.Photo.Length > 0)
            {
                // Köhnə şəkili sil (əgər varsa)
                if (!string.IsNullOrEmpty(userDetails.ImagePath))
                {
                    string oldImagePathFull = Path.Combine(_env.WebRootPath, userDetails.ImagePath.TrimStart('/'));
                    if (System.IO.File.Exists(oldImagePathFull))
                    {
                        System.IO.File.Delete(oldImagePathFull);
                    }
                }

                // Yeni şəkili yüklə
                string folderPath = Path.Combine(_env.WebRootPath, "uploads", "user_profiles");
                if (!Directory.Exists(folderPath)) Directory.CreateDirectory(folderPath);

                string fileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(model.Photo.FileName);
                string filePath = Path.Combine(folderPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await model.Photo.CopyToAsync(stream);
                }
                userDetails.ImagePath = $"/uploads/user_profiles/{fileName}";
            }
            // Əgər yeni şəkil yüklənməyibsə və köhnə şəkil varsa, o qalır.
            // Əgər model.ImagePath birbaşa formdan gəlirsə, onu da yoxlamaq olar.

            if (isNew)
            {
                _context.UserDetails.Add(userDetails);
            }
            else
            {
                _context.UserDetails.Update(userDetails);
            }

            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = "Profil şəkli uğurla yeniləndi.";
            return RedirectToAction(nameof(Index));
        }


        // İstifadəçi yaratma, rol təyin etmə/silmə kimi funksiyalar buraya əlavə edilə bilər.
        // Bu, ASP.NET Core Identity istifadə edirsinizsə UserManager və RoleManager ilə daha asan olur.
    }
}