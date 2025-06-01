using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Hosting;
using FurnitureShopProjectRazil.Models; // About modeli üçün
using System.IO;
using System.Threading.Tasks;
using FurnitureShopProjectRazil.Data; // AppDbContext üçün
using System;
using System.Linq;
using Microsoft.EntityFrameworkCore; // FirstOrDefaultAsync, ToListAsync üçün
// using Microsoft.AspNetCore.Authorization; // Əgər avtorizasiya lazımdırsa

namespace FurnitureShopProjectRazil.Areas.Admin.Controllers
{
    [Area("Admin")]
    // [Authorize(Roles = "Admin")] // Admin roluna sahib istifadəçilər üçün
    public class AboutController : Controller
    {
        private readonly IWebHostEnvironment _env;
        private readonly AppDbContext _context; // AppDbContext istifadə olunur

        public AboutController(AppDbContext context, IWebHostEnvironment env) // AppDbContext istifadə olunur
        {
            _context = context;
            _env = env;
        }

        // INDEX - Məlumatların siyahısı
        public async Task<IActionResult> Index()
        {
            // About cədvəlində adətən tək bir qeyd olur.
            // Əgər birdən çox qeyd ola bilərsə, ToListAsync() istifadə edin.
            // Əgər həmişə tək qeyd olacaqsa, FirstOrDefaultAsync() daha məqsədəuyğundur.
            // Bu nümunədə çoxlu qeyd ola biləcəyi fərz edilir (Index View-nuz List<About> gözləyir)
            var abouts = await _context.Abouts.ToListAsync();
            return View(abouts);
        }

        // CREATE - GET
        [HttpGet]
        public IActionResult Create()
        {
            // Əgər About cədvəlində yalnız bir qeyd olmalıdırsa,
            // və artıq bir qeyd varsa, Create səhifəsinə yönləndirmək əvəzinə
            // mövcud qeydin Update səhifəsinə yönləndirə bilərsiniz.
            if (_context.Abouts.Any())
            {
                // Ehtiyac yoxdursa bu yoxlamanı silə bilərsiniz, nümunənizdə Create view var.
                // TempData["ErrorMessage"] = "Haqqımızda səhifəsi artıq mövcuddur. Yalnız redaktə edə bilərsiniz.";
                // return RedirectToAction(nameof(Index));
            }
            return View();
        }

        // CREATE - POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(About model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (model.Photo != null && model.Photo.Length > 0)
            {
                string folderPath = Path.Combine(_env.WebRootPath, "uploads", "about_images"); // Qovluq adını dəyişə bilərsiniz

                if (!Directory.Exists(folderPath))
                    Directory.CreateDirectory(folderPath);

                string fileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(model.Photo.FileName); // Fayl adına unikal ID və orijinal ad
                string filePath = Path.Combine(folderPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await model.Photo.CopyToAsync(stream);
                }
                model.ImagePath = $"/uploads/about_images/{fileName}"; // Virtual yol
            }

            await _context.Abouts.AddAsync(model);
            await _context.SaveChangesAsync();

            TempData["SuccessMessage"] = "Haqqımızda məlumatı uğurla yaradıldı.";
            return RedirectToAction(nameof(Index));
        }

        // UPDATE - GET
        [HttpGet]
        public async Task<IActionResult> Update(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }
            var model = await _context.Abouts.FirstOrDefaultAsync(x => x.Id == id);
            if (model == null)
            {
                // Əgər About cədvəlində heç bir qeyd yoxdursa və id verilməyibsə,
                // Create səhifəsinə yönləndirə bilərsiniz.
                // Amma sizin nümunənizdə Index-də "Əlavə et" butonu var,
                // və Update-ə konkret id ilə gəlinir.
                return NotFound();
            }
            return View(model);
        }

        // UPDATE - POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(int id, About model)
        {
            if (id != model.Id)
            {
                return NotFound();
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var existingAbout = await _context.Abouts.AsNoTracking().FirstOrDefaultAsync(x => x.Id == model.Id);
            if (existingAbout == null)
            {
                return NotFound();
            }

            // Şəkil yüklənməsi
            if (model.Photo != null && model.Photo.Length > 0)
            {
                // Köhnə şəkili silmək (əgər varsa)
                if (!string.IsNullOrEmpty(existingAbout.ImagePath))
                {
                    string oldImagePathFull = Path.Combine(_env.WebRootPath, existingAbout.ImagePath.TrimStart('/'));
                    if (System.IO.File.Exists(oldImagePathFull))
                    {
                        System.IO.File.Delete(oldImagePathFull);
                    }
                }

                string folderPath = Path.Combine(_env.WebRootPath, "uploads", "about_images");
                if (!Directory.Exists(folderPath))
                    Directory.CreateDirectory(folderPath);

                string fileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(model.Photo.FileName);
                string filePath = Path.Combine(folderPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await model.Photo.CopyToAsync(stream);
                }
                model.ImagePath = $"/uploads/about_images/{fileName}"; // Yeni şəklin yolu modelə mənimsədilir
            }
            else
            {
                // Yeni şəkil yüklənməyibsə, köhnə şəkil yolunu qoru
                model.ImagePath = existingAbout.ImagePath;
            }

            try
            {
                _context.Update(model); // Bütün sahələri modeldən götürür
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!_context.Abouts.Any(e => e.Id == model.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }
            TempData["SuccessMessage"] = "Haqqımızda məlumatı uğurla yeniləndi.";
            return RedirectToAction(nameof(Index));
        }

        // DELETE - GET (Təsdiqləmə səhifəsi üçün)
        [HttpGet]
        // Route atributu nümunənizdəki kimidir, amma standart MVC routing ilə də işləyir:
        // [Route("Admin/About/Delete/{id}")]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }
            var model = await _context.Abouts.FirstOrDefaultAsync(x => x.Id == id);
            if (model == null)
            {
                return NotFound();
            }
            return View(model);
        }

        // DELETE - POST (Silmə üçün)
        [HttpPost, ActionName("Delete")] // ActionName("Delete") Delete.cshtml-dəki formun asp-action="Delete" olması üçün
        [ValidateAntiForgeryToken]
        // Route atributu nümunənizdəki kimidir.
        // [Route("Admin/About/Delete")] // Bu halda id formun içində <input type="hidden" asp-for="Id" /> ilə gəlir
        // Əgər DeleteConfirmed(int id) parametrini istifadə edirsinizsə, route-da id olmalıdır:
        // [HttpPost("Admin/About/Delete/{id}")] // və ya sadəcə [HttpPost] və parametr olaraq int id
        public async Task<IActionResult> DeleteConfirmed(int id) // Parametr adı id olmalıdır
        {
            var model = await _context.Abouts.FindAsync(id);
            if (model == null)
            {
                return NotFound();
            }

            // Şəkili serverdən silmək (əgər varsa)
            if (!string.IsNullOrEmpty(model.ImagePath))
            {
                string imagePathFull = Path.Combine(_env.WebRootPath, model.ImagePath.TrimStart('/'));
                if (System.IO.File.Exists(imagePathFull))
                {
                    System.IO.File.Delete(imagePathFull);
                }
            }

            _context.Abouts.Remove(model);
            await _context.SaveChangesAsync();

            TempData["SuccessMessage"] = "Haqqımızda məlumatı uğurla silindi.";
            return RedirectToAction(nameof(Index));
        }
    }
}