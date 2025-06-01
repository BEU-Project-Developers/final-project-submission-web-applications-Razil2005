using FurnitureShopProjectRazil.Data; // AppDbContext üçün
using FurnitureShopProjectRazil.Models; // About modeli üçün
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore; // FirstOrDefaultAsync üçün
using System.Linq; // FirstOrDefaultAsync üçün (bəzən tələb olunur)
using System.Threading.Tasks; // async/await üçün

namespace FurnitureShopProjectRazil.Controllers
{
    public class AboutController : Controller
    {
        private readonly AppDbContext _context;

        public AboutController(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
           
            About? aboutData = await _context.Abouts.FirstOrDefaultAsync();

            if (aboutData == null)
            {
              return NotFound();
            }

            return View(aboutData); // About məlumatını View-a ötürürük
        }
    }
}