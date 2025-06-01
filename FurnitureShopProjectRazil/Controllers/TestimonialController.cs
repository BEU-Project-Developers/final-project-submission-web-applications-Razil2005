// Controllers/TestimonialsController.cs
using FurnitureShopProjectRazil.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading.Tasks;

namespace FurnitureShopProjectRazil.Controllers
{
    public class TestimonialsController : Controller
    {
        private readonly AppDbContext _context;
        // ILogger istifadə etmək istəsəniz:
        // private readonly ILogger<TestimonialsController> _logger;

        public TestimonialsController(AppDbContext context /*, ILogger<TestimonialsController> logger */)
        {
            _context = context;
            // _logger = logger;
        }

        // GET: Testimonials
        // Bu action testimonial-lərin göstərildiyi səhifə üçün istifadə ediləcək.
        // Əgər bu hissə başqa səhifələrdə (məsələn, ana səhifədə) partial view kimi istifadə ediləcəksə,
        // o zaman PartialViewResult qaytaran bir action da yarada bilərsiniz.
        public async Task<IActionResult> Index()
        {
            var testimonials = await _context.Testimonials
                                         .OrderByDescending(t => t.DatePosted) // Ən yeni rəylər əvvəldə
                                         .ToListAsync();
            return View(testimonials);
        }

        // Admin paneli üçün CRUD əməliyyatları (Create, Edit, Delete)
        // adətən ayrı bir controller-də (məsələn, Admin/TestimonialsController) olur.
        // Bu controller yalnız istifadəçi tərəfindən görünən hissə üçündür.
    }
}