using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Hosting;
using FurnitureShopProjectRazil.Models;
using System.IO;
using System.Threading.Tasks;
using FurnitureShopProjectRazil.Data;
using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
// using Microsoft.AspNetCore.Authorization;

namespace FurnitureShopProjectRazil.Areas.Admin.Controllers
{
    [Area("Admin")]
    // [Authorize(Roles = "Admin")]
    public class TestimonialController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;

        public TestimonialController(AppDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }

        // INDEX
        public async Task<IActionResult> Index()
        {
            var testimonials = await _context.Testimonials
                                         .OrderByDescending(t => t.DatePosted)
                                         .ToListAsync();
            return View(testimonials);
        }

        // CREATE - GET
        [HttpGet]
        public IActionResult Create()
        {
            // DatePosted avtomatik təyin olunduğu üçün burada bir şey etməyə ehtiyac yoxdur.
            return View(new Testimonial()); // Boş model göndəririk ki, DatePosted default dəyərini alsın.
        }

        // CREATE - POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Testimonial testimonial)
        {
            // DatePosted modeldə avtomatik təyin olunur, lakin post zamanı gəlmirsə və ya dəyişdirilibsə,
            // yenidən təyin etmək olar və ya modeldəki default dəyərə etibar etmək olar.
            // testimonial.DatePosted = DateTime.UtcNow; // Əgər hər zaman yeni tarix olmasını istəyirsinizsə

            if (ModelState.IsValid)
            {
                if (testimonial.Photo != null && testimonial.Photo.Length > 0)
                {
                    string folderPath = Path.Combine(_env.WebRootPath, "uploads", "testimonials");
                    if (!Directory.Exists(folderPath))
                    {
                        Directory.CreateDirectory(folderPath);
                    }
                    string fileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(testimonial.Photo.FileName);
                    string filePath = Path.Combine(folderPath, fileName);

                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await testimonial.Photo.CopyToAsync(stream);
                    }
                    testimonial.ImagePath = $"/uploads/testimonials/{fileName}";
                }
                else
                {
                    testimonial.ImagePath = null; // Şəkil yüklənməyibsə
                }

                // DatePosted avtomatik təyin olunacaq əgər gəlməyibsə
                if (testimonial.DatePosted == default(DateTime))
                {
                    testimonial.DatePosted = DateTime.UtcNow;
                }


                await _context.Testimonials.AddAsync(testimonial);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "Rəy uğurla yaradıldı.";
                return RedirectToAction(nameof(Index));
            }
            return View(testimonial);
        }

        // UPDATE - GET
        [HttpGet]
        public async Task<IActionResult> Update(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var testimonial = await _context.Testimonials.FindAsync(id);
            if (testimonial == null)
            {
                return NotFound();
            }
            return View(testimonial);
        }

        // UPDATE - POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(int id, Testimonial testimonial)
        {
            if (id != testimonial.Id)
            {
                return NotFound();
            }

            // DatePosted sahəsini əl ilə update etmək istəmiriksə və ya
            // formdan gəlmirsə, köhnə dəyəri qorumaq və ya yenidən təyin etmək lazımdır.
            // Bu nümunədə formdan gəldiyini fərz edirik (hidden input ilə göndərilə bilər).
            // Əgər dəyişməsini istəmirsinizsə:
            // var existingTestimonialForDate = await _context.Testimonials.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id);
            // testimonial.DatePosted = existingTestimonialForDate.DatePosted;

            if (ModelState.IsValid)
            {
                var existingTestimonial = await _context.Testimonials.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id);
                if (existingTestimonial == null) return NotFound();

                if (testimonial.Photo != null && testimonial.Photo.Length > 0)
                {
                    // Köhnə şəkili sil
                    if (!string.IsNullOrEmpty(existingTestimonial.ImagePath))
                    {
                        string oldImagePathFull = Path.Combine(_env.WebRootPath, existingTestimonial.ImagePath.TrimStart('/'));
                        if (System.IO.File.Exists(oldImagePathFull))
                        {
                            System.IO.File.Delete(oldImagePathFull);
                        }
                    }

                    // Yeni şəkili yüklə
                    string folderPath = Path.Combine(_env.WebRootPath, "uploads", "testimonials");
                    if (!Directory.Exists(folderPath)) Directory.CreateDirectory(folderPath);
                    string fileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(testimonial.Photo.FileName);
                    string filePath = Path.Combine(folderPath, fileName);
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await testimonial.Photo.CopyToAsync(stream);
                    }
                    testimonial.ImagePath = $"/uploads/testimonials/{fileName}";
                }
                else
                {
                    // Yeni şəkil yüklənməyibsə, köhnə ImagePath-i qoru
                    testimonial.ImagePath = existingTestimonial.ImagePath;
                }

                try
                {
                    // DatePosted-in dəyərini qorumaq üçün (əgər formda yoxdursa)
                    if (testimonial.DatePosted == default(DateTime) && existingTestimonial != null)
                    {
                        testimonial.DatePosted = existingTestimonial.DatePosted;
                    }
                    else if (testimonial.DatePosted == default(DateTime)) // Əgər hələ də defaultdursa, yenidən təyin et
                    {
                        testimonial.DatePosted = DateTime.UtcNow;
                    }


                    _context.Update(testimonial);
                    await _context.SaveChangesAsync();
                    TempData["SuccessMessage"] = "Rəy uğurla yeniləndi.";
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TestimonialExists(testimonial.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(testimonial);
        }

        // DELETE - GET
        [HttpGet]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var testimonial = await _context.Testimonials.FirstOrDefaultAsync(m => m.Id == id);
            if (testimonial == null)
            {
                return NotFound();
            }

            return View(testimonial);
        }

        // DELETE - POST
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var testimonial = await _context.Testimonials.FindAsync(id);
            if (testimonial == null)
            {
                TempData["ErrorMessage"] = "Rəy tapılmadı.";
                return RedirectToAction(nameof(Index));
            }

            // Şəkili serverdən sil
            if (!string.IsNullOrEmpty(testimonial.ImagePath))
            {
                string imagePathFull = Path.Combine(_env.WebRootPath, testimonial.ImagePath.TrimStart('/'));
                if (System.IO.File.Exists(imagePathFull))
                {
                    System.IO.File.Delete(imagePathFull);
                }
            }

            _context.Testimonials.Remove(testimonial);
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = "Rəy uğurla silindi.";
            return RedirectToAction(nameof(Index));
        }

        private bool TestimonialExists(int id)
        {
            return _context.Testimonials.Any(e => e.Id == id);
        }
    }
}