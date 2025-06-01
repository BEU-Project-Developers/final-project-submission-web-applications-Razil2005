using Microsoft.AspNetCore.Mvc;

namespace FurnitureShopProjectRazil.Controllers
{
    public class GalleryController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
